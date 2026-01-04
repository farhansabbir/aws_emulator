from flask import Flask, request, Response
import uuid
import datetime

app = Flask(__name__)

# ==========================================
# RELATIONAL STATE STORE
# ==========================================
public_ip_pool = [f"203.0.113.{i}" for i in range(1, 101)]
eip_pool = [f"52.99.100.{i}" for i in range(1, 51)]

state = {
    "vpcs": {}, 
    "subnets": {}, 
    "route_tables": {}, 
    "security_groups": {}, 
    "network_acls": {},
    "instances": {},
    "network_interfaces": {}, 
    "internet_gateways": {},
    "nat_gateways": {},
    "addresses": {},
    "account_id": "123456789012",
}

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def get_filter(form_data, filter_name):
    """Retrieves a value for a specific filter name or direct ID parameter."""
    for key, val in form_data.items():
        if val == filter_name: 
            prefix = key.rsplit('.', 1)[0] 
            return form_data.get(f"{prefix}.Value.1")
            
    mapping = {
        'group-id': "GroupId.1", 'vpc-id': "VpcId.1", 'group-name': "GroupName.1",
        'subnet-id': "SubnetId.1", 'instance-id': "InstanceId.1", 
        'network-interface-id': "NetworkInterfaceId.1", 'instance-type': "InstanceType.1",
        'internet-gateway-id': "InternetGatewayId.1", 'nat-gateway-id': "NatGatewayId.1",
        'allocation-id': "AllocationId.1"
    }
    return form_data.get(mapping.get(filter_name))

def xml_wrapper(action, content):
    return f'<{action}Response xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>{uuid.uuid4()}</requestId>{content}</{action}Response>'

def find_resource_by_id(res_id):
    for category in state.values():
        if isinstance(category, dict) and res_id in category:
            return category[res_id]
    return None

def allocate_public_ip():
    if public_ip_pool: return public_ip_pool.pop(0)
    return None

def allocate_eip():
    if eip_pool: return eip_pool.pop(0)
    return None

# ==========================================
# MAIN GATEWAY
# ==========================================
@app.route("/", methods=["POST"])
def gateway():
    action = request.form.get("Action")
    print(f"--- Action: {action} ---")

    # ------------------------------------------
    # 1. IDENTITY & ATTRIBUTES
    # ------------------------------------------
    if action == "GetCallerIdentity":
        content = f"<GetCallerIdentityResult><Arn>arn:aws:iam::{state['account_id']}:user/emulator</Arn><UserId>AIDACKCEVSQ6C2EXAMPLE</UserId><Account>{state['account_id']}</Account></GetCallerIdentityResult>"
        return Response(xml_wrapper(action, content), mimetype='text/xml')
    
    elif action == "GetUser":
        content = f"<GetUserResult><User><UserName>emulator</UserName><Arn>arn:aws:iam::{state['account_id']}:user/emulator</Arn></User></GetUserResult>"
        return Response(xml_wrapper(action, content), mimetype='text/xml')

    elif action == "DescribeVpcAttribute":
        vpc_id, attr = request.form.get("VpcId"), request.form.get("Attribute")
        content = f"<vpcId>{vpc_id}</vpcId><{attr}><value>true</value></{attr}>"
        return Response(xml_wrapper(action, content), mimetype='text/xml')

    # ------------------------------------------
    # 2. INSTANCE ATTRIBUTES
    # ------------------------------------------
    elif action == "DescribeInstanceAttribute":
        inst_id = request.form.get("InstanceId")
        attr = request.form.get("Attribute")
        
        stored_val = None
        if inst_id in state["instances"]:
             if attr == "groupSet":
                 eni_id = state["instances"][inst_id].get("eni_id")
                 if eni_id and eni_id in state["network_interfaces"]:
                     sgs = state["network_interfaces"][eni_id].get("security_groups", [])
                     items = "".join([f"<item><groupId>{sg}</groupId></item>" for sg in sgs])
                     return Response(xml_wrapper(action, f"<instanceId>{inst_id}</instanceId><groupSet>{items}</groupSet>"), mimetype='text/xml')
             stored_val = state["instances"][inst_id].get("attrs", {}).get(attr)

        if stored_val is None:
            if attr == "instanceInitiatedShutdownBehavior": stored_val = "stop"
            elif attr == "disableApiTermination": stored_val = "false"
            elif attr == "userData": stored_val = "" 
            elif attr == "rootDeviceName": stored_val = "/dev/sda1"
            elif attr == "sourceDestCheck": stored_val = "true"
            else: stored_val = "true"
        
        content = f"<instanceId>{inst_id}</instanceId><{attr}><value>{stored_val}</value></{attr}>"
        return Response(xml_wrapper(action, content), mimetype='text/xml')

    elif action == "ModifyInstanceAttribute":
        inst_id = request.form.get("InstanceId")
        if inst_id in state["instances"]:
            if request.form.get("SourceDestCheck.Value"):
                state["instances"][inst_id]["attrs"]["sourceDestCheck"] = request.form.get("SourceDestCheck.Value")
            if request.form.get("InstanceInitiatedShutdownBehavior.Value"):
                state["instances"][inst_id]["attrs"]["instanceInitiatedShutdownBehavior"] = request.form.get("InstanceInitiatedShutdownBehavior.Value")
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    # ------------------------------------------
    # 3. TAGGING & TEMPLATES
    # ------------------------------------------
    elif action == "CreateTags":
        res_id = request.form.get("ResourceId.1")
        resource = find_resource_by_id(res_id)
        if resource:
            for key, value in request.form.items():
                if "Tag." in key and ".Key" in key:
                    idx = key.split('.')[1]
                    tag_key = value
                    tag_val = request.form.get(f"Tag.{idx}.Value")
                    resource["tags"][tag_key] = tag_val
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    elif action == "DescribeTags":
        target_id = get_filter(request.form, 'resource-id')
        items = ""
        if target_id:
            res = find_resource_by_id(target_id)
            if res:
                for k, v in res.get("tags", {}).items():
                    items += f"<item><resourceId>{target_id}</resourceId><resourceType>resource</resourceType><key>{k}</key><value>{v}</value></item>"
        return Response(xml_wrapper(action, f"<tagSet>{items}</tagSet>"), mimetype='text/xml')

    elif action == "DescribeLaunchTemplates":
        return Response(xml_wrapper(action, "<launchTemplates/>"), mimetype='text/xml')

    # ------------------------------------------
    # 4. NETWORK INTERFACES & EIPS
    # ------------------------------------------
    elif action == "DescribeNetworkInterfaces":
        target_id = get_filter(request.form, 'network-interface-id')
        items = ""
        for eni_id, d in state["network_interfaces"].items():
            if target_id and eni_id != target_id: continue
            
            sg_xml = "".join([f"<item><groupId>{sg}</groupId><groupName>default</groupName></item>" for sg in d.get('security_groups', [])])
            association_xml = f"<association><publicIp>{d['public_ip']}</publicIp><ipOwnerId>amazon</ipOwnerId></association>" if d.get('public_ip') else ""

            items += f"""<item><networkInterfaceId>{eni_id}</networkInterfaceId><subnetId>{d['subnet_id']}</subnetId><vpcId>{d['vpc_id']}</vpcId><description>{d.get('desc', 'Primary network interface')}</description><ownerId>{state['account_id']}</ownerId><status>in-use</status><macAddress>02:00:00:00:00:00</macAddress><privateIpAddress>{d['private_ip']}</privateIpAddress><sourceDestCheck>true</sourceDestCheck><groupSet>{sg_xml}</groupSet>{association_xml}<attachment><attachmentId>eni-attach-{uuid.uuid4().hex[:8]}</attachmentId><instanceId>{d['attachment']['instance_id']}</instanceId><deviceIndex>0</deviceIndex><status>attached</status><attachTime>{datetime.datetime.utcnow().isoformat()}Z</attachTime><deleteOnTermination>true</deleteOnTermination></attachment></item>"""
        return Response(xml_wrapper(action, f"<networkInterfaceSet>{items}</networkInterfaceSet>"), mimetype='text/xml')

    elif action == "ModifyNetworkInterfaceAttribute":
        eni_id = request.form.get("NetworkInterfaceId")
        if eni_id in state["network_interfaces"]:
            if "SecurityGroupId.1" in request.form:
                new_sgs = []
                for key, value in request.form.items():
                    if "SecurityGroupId." in key: new_sgs.append(value)
                state["network_interfaces"][eni_id]["security_groups"] = new_sgs
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    elif action == "AllocateAddress":
        alloc_id = f"eipalloc-{uuid.uuid4().hex[:8]}"
        public_ip = allocate_eip()
        state["addresses"][alloc_id] = {"public_ip": public_ip, "allocation_id": alloc_id}
        content = f"<allocationId>{alloc_id}</allocationId><publicIp>{public_ip}</publicIp><domain>vpc</domain>"
        return Response(xml_wrapper(action, content), mimetype='text/xml')

    elif action == "DescribeAddresses":
        target_id = get_filter(request.form, 'allocation-id')
        items = ""
        for alloc_id, d in state["addresses"].items():
            if target_id and alloc_id != target_id: continue
            items += f"<item><allocationId>{alloc_id}</allocationId><publicIp>{d['public_ip']}</publicIp><domain>vpc</domain></item>"
        return Response(xml_wrapper(action, f"<addressesSet>{items}</addressesSet>"), mimetype='text/xml')

    # THE FIX IS HERE: Correct parameter extraction
    elif action == "DescribeAddressesAttribute":
        # Terraform sends AllocationId.1, not AllocationId
        alloc_id = get_filter(request.form, 'allocation-id')
        if alloc_id and alloc_id in state["addresses"]:
            content = f"<allocationId>{alloc_id}</allocationId><domain>vpc</domain>"
            return Response(xml_wrapper(action, content), mimetype='text/xml')
        return Response(xml_wrapper(action, ""), status=400, mimetype='text/xml')

    elif action == "ReleaseAddress":
        target_id = request.form.get("AllocationId")
        if target_id in state["addresses"]: del state["addresses"][target_id]
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    # ------------------------------------------
    # 5. GATEWAYS (IGW & NATGW)
    # ------------------------------------------
    elif action == "CreateInternetGateway":
        igw_id = f"igw-{uuid.uuid4().hex[:8]}"
        state["internet_gateways"][igw_id] = {"attachments": [], "tags": {}}
        return Response(xml_wrapper(action, f"<internetGateway><internetGatewayId>{igw_id}</internetGatewayId><attachmentSet/></internetGateway>"), mimetype='text/xml')

    elif action == "AttachInternetGateway":
        igw_id = request.form.get("InternetGatewayId")
        vpc_id = request.form.get("VpcId")
        if igw_id in state["internet_gateways"]:
            state["internet_gateways"][igw_id]["attachments"].append(vpc_id)
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    elif action == "DetachInternetGateway":
        igw_id = request.form.get("InternetGatewayId")
        vpc_id = request.form.get("VpcId")
        if igw_id in state["internet_gateways"]:
             state["internet_gateways"][igw_id]["attachments"] = [a for a in state["internet_gateways"][igw_id]["attachments"] if a != vpc_id]
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    elif action == "DescribeInternetGateways":
        target_id = get_filter(request.form, 'internet-gateway-id')
        items = ""
        for igw_id, d in state["internet_gateways"].items():
            if target_id and igw_id != target_id: continue
            attachments = "".join([f"<item><vpcId>{vpc}</vpcId><state>available</state></item>" for vpc in d['attachments']])
            items += f"<item><internetGatewayId>{igw_id}</internetGatewayId><attachmentSet>{attachments}</attachmentSet></item>"
        return Response(xml_wrapper(action, f"<internetGatewaySet>{items}</internetGatewaySet>"), mimetype='text/xml')

    elif action == "DeleteInternetGateway":
        target_id = request.form.get("InternetGatewayId")
        if target_id in state["internet_gateways"]: del state["internet_gateways"][target_id]
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    elif action == "CreateNatGateway":
        nat_id = f"nat-{uuid.uuid4().hex[:8]}"
        subnet_id = request.form.get("SubnetId")
        alloc_id = request.form.get("AllocationId")
        public_ip = state["addresses"].get(alloc_id, {}).get("public_ip", "0.0.0.0")
        state["nat_gateways"][nat_id] = {
            "subnet_id": subnet_id, "allocation_id": alloc_id, 
            "vpc_id": state["subnets"][subnet_id]["vpc_id"], "state": "available", "tags": {},
            "public_ip": public_ip
        }
        content = f"""<natGateway><natGatewayId>{nat_id}</natGatewayId><subnetId>{subnet_id}</subnetId><vpcId>{state["nat_gateways"][nat_id]["vpc_id"]}</vpcId><state>available</state><natGatewayAddressSet><item><allocationId>{alloc_id}</allocationId><publicIp>{public_ip}</publicIp></item></natGatewayAddressSet></natGateway>"""
        return Response(xml_wrapper(action, content), mimetype='text/xml')

    elif action == "DescribeNatGateways":
        target_id = get_filter(request.form, 'nat-gateway-id')
        items = ""
        for nat_id, d in state["nat_gateways"].items():
            if target_id and nat_id != target_id: continue
            items += f"""<item><natGatewayId>{nat_id}</natGatewayId><subnetId>{d['subnet_id']}</subnetId><vpcId>{d['vpc_id']}</vpcId><state>{d['state']}</state><natGatewayAddressSet><item><allocationId>{d['allocation_id']}</allocationId><publicIp>{d.get('public_ip')}</publicIp></item></natGatewayAddressSet></item>"""
        return Response(xml_wrapper(action, f"<natGatewaySet>{items}</natGatewaySet>"), mimetype='text/xml')

    elif action == "DeleteNatGateway":
        target_id = request.form.get("NatGatewayId")
        if target_id in state["nat_gateways"]: 
            state["nat_gateways"][target_id]["state"] = "deleted"
        return Response(xml_wrapper(action, f"<natGatewayId>{target_id}</natGatewayId>"), mimetype='text/xml')

    # ------------------------------------------
    # 6. ROUTING & SECURITY
    # ------------------------------------------
    elif action == "CreateRoute":
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    elif action == "DeleteRoute":
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    elif action == "DescribeSecurityGroups":
        target_id = get_filter(request.form, 'group-id')
        target_vpc = get_filter(request.form, 'vpc-id')
        target_name = get_filter(request.form, 'group-name')

        items = ""
        for sg_id, d in state["security_groups"].items():
            if target_id and sg_id != target_id: continue
            if target_vpc and d['vpc_id'] != target_vpc: continue
            if target_name and d['name'] != target_name: continue

            ingress = "".join([f"<item><ipProtocol>{r['proto']}</ipProtocol><fromPort>{r['from']}</fromPort><toPort>{r['to']}</toPort><ipRanges><item><cidrIp>{r['cidr']}</cidrIp></item></ipRanges></item>" for r in d.get('ingress', [])])
            items += f"<item><ownerId>{state['account_id']}</ownerId><groupId>{sg_id}</groupId><groupName>{d['name']}</groupName><vpcId>{d['vpc_id']}</vpcId><ipPermissions>{ingress}</ipPermissions><ipPermissionsEgress/></item>"
        return Response(xml_wrapper(action, f"<securityGroupInfo>{items}</securityGroupInfo>"), mimetype='text/xml')

    elif action == "DescribeSecurityGroupRules":
        target_group = get_filter(request.form, 'group-id')
        rules_xml = ""
        for sg_id, data in state["security_groups"].items():
            if target_group and sg_id != target_group: continue
            for rule in data.get("ingress", []):
                rules_xml += f"""<item><securityGroupRuleId>{rule['id']}</securityGroupRuleId><groupId>{sg_id}</groupId><ownerId>{state['account_id']}</ownerId><isEgress>false</isEgress><ipProtocol>{rule['proto']}</ipProtocol><fromPort>{rule['from']}</fromPort><toPort>{rule['to']}</toPort><cidrIpv4>{rule['cidr']}</cidrIpv4></item>"""
        return Response(xml_wrapper(action, f"<securityGroupRuleSet>{rules_xml}</securityGroupRuleSet>"), mimetype='text/xml')

    elif action == "AuthorizeSecurityGroupIngress":
        sg_id = request.form.get("GroupId")
        if sg_id in state["security_groups"]:
            rule_id = f"sgr-{uuid.uuid4().hex[:8]}"
            rule = {"id": rule_id, "proto": request.form.get("IpPermissions.1.IpProtocol", "-1"), "from": request.form.get("IpPermissions.1.FromPort", "0"), "to": request.form.get("IpPermissions.1.ToPort", "65535"), "cidr": request.form.get("IpPermissions.1.IpRanges.1.CidrIp", "0.0.0.0/0")}
            state["security_groups"][sg_id]["ingress"].append(rule)
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    elif action == "RevokeSecurityGroupIngress":
        rule_id = request.form.get("SecurityGroupRuleIds.1")
        if rule_id:
            for sg in state["security_groups"].values(): sg["ingress"] = [r for r in sg["ingress"] if r["id"] != rule_id]
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    elif action == "DeleteSecurityGroup":
        target_id = request.form.get("GroupId")
        if target_id in state["security_groups"]: del state["security_groups"][target_id]
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    # ------------------------------------------
    # 7. EC2 INSTANCE OPERATIONS
    # ------------------------------------------
    elif action == "DescribeInstanceTypes":
        req_type = get_filter(request.form, 'instance-type') or "t2.micro"
        xml_body = f"""<instanceTypeSet><item><instanceType>{req_type}</instanceType><processorInfo><supportedArchitectures><item>x86_64</item></supportedArchitectures></processorInfo><vCpuInfo><defaultVCpus>1</defaultVCpus></vCpuInfo><memoryInfo><sizeInMiB>1024</sizeInMiB></memoryInfo><instanceStorageSupported>false</instanceStorageSupported></item></instanceTypeSet>"""
        return Response(xml_wrapper(action, xml_body), mimetype='text/xml')

    elif action == "RunInstances":
        inst_id = f"i-{uuid.uuid4().hex[:8]}"
        res_id = f"r-{uuid.uuid4().hex[:8]}"
        eni_id = f"eni-{uuid.uuid4().hex[:8]}"
        
        image_id = request.form.get("ImageId")
        inst_type = request.form.get("InstanceType")
        subnet_id = request.form.get("SubnetId")
        
        security_groups = []
        for key, value in request.form.items():
            if "SecurityGroupId." in key: security_groups.append(value)

        vpc_id = state['subnets'].get(subnet_id, {}).get('vpc_id', 'vpc-unknown')
        private_ip = f"10.0.1.{len(state['instances']) + 10}" 
        
        public_ip = None
        subnet_config = state['subnets'].get(subnet_id, {})
        if subnet_config.get('map_public_ip_on_launch') == 'true': public_ip = allocate_public_ip()

        state["instances"][inst_id] = {
            "id": inst_id, "res_id": res_id, "eni_id": eni_id, "image_id": image_id, "type": inst_type,
            "subnet_id": subnet_id, "vpc_id": vpc_id, "private_ip": private_ip, "public_ip": public_ip,
            "state_code": "16", "state_name": "running", "tags": {}, "attrs": {} 
        }

        state["network_interfaces"][eni_id] = {
            "id": eni_id, "subnet_id": subnet_id, "vpc_id": vpc_id, "private_ip": private_ip, "public_ip": public_ip,
            "security_groups": security_groups, "tags": {}, "attachment": {"instance_id": inst_id, "device_index": 0}
        }

        xml_body = f"""<reservationId>{res_id}</reservationId><ownerId>{state['account_id']}</ownerId><instancesSet><item><instanceId>{inst_id}</instanceId><imageId>{image_id}</imageId><instanceState><code>16</code><name>running</name></instanceState><privateIpAddress>{private_ip}</privateIpAddress><vpcId>{vpc_id}</vpcId><subnetId>{subnet_id}</subnetId><instanceType>{inst_type}</instanceType></item></instancesSet>"""
        return Response(xml_wrapper(action, xml_body), mimetype='text/xml')

    elif action == "DescribeInstances":
        target_id = get_filter(request.form, 'instance-id')
        reservations_xml = ""
        for i_id, d in state["instances"].items():
            if target_id and i_id != target_id: continue
            
            tags_xml = "".join([f"<item><key>{k}</key><value>{v}</value></item>" for k, v in d.get("tags", {}).items()])
            eni = state["network_interfaces"].get(d['eni_id'], {})
            sg_xml = "".join([f"<item><groupId>{sg}</groupId><groupName>sg-name</groupName></item>" for sg in eni.get('security_groups', [])])

            association_xml = f"<association><publicIp>{d['public_ip']}</publicIp><ipOwnerId>amazon</ipOwnerId></association>" if d.get('public_ip') else ""
            public_ip_tag = f"<ipAddress>{d['public_ip']}</ipAddress>" if d.get('public_ip') else ""

            eni_xml = f"""<item><networkInterfaceId>{d['eni_id']}</networkInterfaceId><subnetId>{d['subnet_id']}</subnetId><vpcId>{d['vpc_id']}</vpcId><description>Primary</description><ownerId>{state['account_id']}</ownerId><status>in-use</status><macAddress>02:00:00:00:00:00</macAddress><privateIpAddress>{d['private_ip']}</privateIpAddress><sourceDestCheck>true</sourceDestCheck><groupSet>{sg_xml}</groupSet>{association_xml}<attachment><attachmentId>eni-attach-{uuid.uuid4().hex[:8]}</attachmentId><deviceIndex>0</deviceIndex><status>attached</status><attachTime>{datetime.datetime.utcnow().isoformat()}Z</attachTime><deleteOnTermination>true</deleteOnTermination></attachment></item>"""

            reservations_xml += f"""<item><reservationId>{d['res_id']}</reservationId><ownerId>{state['account_id']}</ownerId><instancesSet><item><instanceId>{i_id}</instanceId><imageId>{d['image_id']}</imageId><instanceState><code>{d['state_code']}</code><name>{d['state_name']}</name></instanceState><privateIpAddress>{d['private_ip']}</privateIpAddress>{public_ip_tag}<vpcId>{d['vpc_id']}</vpcId><subnetId>{d['subnet_id']}</subnetId><instanceType>{d['type']}</instanceType><tagSet>{tags_xml}</tagSet><groupSet>{sg_xml}</groupSet><networkInterfaceSet>{eni_xml}</networkInterfaceSet><architecture>x86_64</architecture><rootDeviceType>ebs</rootDeviceType><virtualizationType>hvm</virtualizationType></item></instancesSet></item>"""
        return Response(xml_wrapper(action, f"<reservationSet>{reservations_xml}</reservationSet>"), mimetype='text/xml')

    elif action == "DescribeInstanceStatus":
        target_id = get_filter(request.form, 'instance-id')
        items = ""
        for i_id, d in state["instances"].items():
            if target_id and i_id != target_id: continue
            if d['state_name'] == 'terminated': continue 
            items += f"""<item><instanceId>{i_id}</instanceId><availabilityZone>us-east-1a</availabilityZone><instanceState><code>{d['state_code']}</code><name>{d['state_name']}</name></instanceState><systemStatus><status>ok</status><details/></systemStatus><instanceStatus><status>ok</status><details/></instanceStatus></item>"""
        return Response(xml_wrapper(action, f"<instanceStatusSet>{items}</instanceStatusSet>"), mimetype='text/xml')

    elif action == "TerminateInstances":
        target_id = request.form.get("InstanceId.1")
        if target_id and target_id in state["instances"]:
            state["instances"][target_id]['state_code'] = "48"
            state["instances"][target_id]['state_name'] = "terminated"
        xml_body = f"""<instancesSet><item><instanceId>{target_id}</instanceId><currentState><code>48</code><name>terminated</name></currentState><previousState><code>16</code><name>running</name></previousState></item></instancesSet>"""
        return Response(xml_wrapper(action, xml_body), mimetype='text/xml')

    # ------------------------------------------
    # 8. DISCOVERY & CREATION (STANDARD)
    # ------------------------------------------
    elif action == "DescribeVpcs":
        target_id = get_filter(request.form, 'vpc-id')
        items = ""
        for id, d in state["vpcs"].items():
            if target_id and id != target_id: continue
            items += f"<item><vpcId>{id}</vpcId><state>available</state><cidrBlock>{d['cidr']}</cidrBlock><isDefault>false</isDefault><instanceTenancy>default</instanceTenancy></item>"
        return Response(xml_wrapper(action, f"<vpcSet>{items}</vpcSet>"), mimetype='text/xml')

    elif action == "DescribeSubnets":
        target_id = get_filter(request.form, 'subnet-id')
        target_vpc = get_filter(request.form, 'vpc-id')
        items = ""
        for s_id, d in state["subnets"].items():
            if target_id and s_id != target_id: continue
            if target_vpc and d['vpc_id'] != target_vpc: continue
            map_public = d.get('map_public_ip_on_launch', 'false')
            items += f"""<item><subnetId>{s_id}</subnetId><vpcId>{d['vpc_id']}</vpcId><cidrBlock>{d['cidr']}</cidrBlock><availabilityZone>us-east-1a</availabilityZone><availableIpAddressCount>251</availableIpAddressCount><state>available</state><mapPublicIpOnLaunch>{map_public}</mapPublicIpOnLaunch></item>"""
        return Response(xml_wrapper(action, f"<subnetSet>{items}</subnetSet>"), mimetype='text/xml')

    elif action == "ModifySubnetAttribute":
        s_id = request.form.get("SubnetId")
        if s_id in state["subnets"]:
            val = request.form.get("MapPublicIpOnLaunch.Value")
            if val: state["subnets"][s_id]["map_public_ip_on_launch"] = val
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    elif action == "DescribeNetworkAcls":
        target_vpc = get_filter(request.form, 'vpc-id')
        items = ""
        for acl_id, d in state["network_acls"].items():
            if target_vpc and d['vpc_id'] != target_vpc: continue
            items += f"<item><networkAclId>{acl_id}</networkAclId><vpcId>{d['vpc_id']}</vpcId><default>true</default><entrySet><item><ruleNumber>100</ruleNumber><protocol>-1</protocol><ruleAction>allow</ruleAction><egress>true</egress><cidrBlock>0.0.0.0/0</cidrBlock></item></entrySet></item>"
        return Response(xml_wrapper(action, f"<networkAclSet>{items}</networkAclSet>"), mimetype='text/xml')

    elif action == "DescribeRouteTables":
        target_vpc = get_filter(request.form, 'vpc-id')
        items = ""
        for rtb_id, d in state["route_tables"].items():
            if target_vpc and d['vpc_id'] != target_vpc: continue
            items += f"<item><routeTableId>{rtb_id}</routeTableId><vpcId>{d['vpc_id']}</vpcId><associationSet><item><main>true</main></item></associationSet></item>"
        return Response(xml_wrapper(action, f"<routeTableSet>{items}</routeTableSet>"), mimetype='text/xml')

    elif action == "CreateVpc":
        vpc_id = f"vpc-{uuid.uuid4().hex[:8]}"
        state["vpcs"][vpc_id] = {"cidr": request.form.get("CidrBlock"), "tags": {}}
        state["network_acls"][f"acl-{uuid.uuid4().hex[:8]}"] = {"vpc_id": vpc_id, "tags": {}}
        state["route_tables"][f"rtb-{uuid.uuid4().hex[:8]}"] = {"vpc_id": vpc_id, "tags": {}}
        state["security_groups"][f"sg-{uuid.uuid4().hex[:8]}"] = {"vpc_id": vpc_id, "name": "default", "desc": "default", "ingress": [], "tags": {}}
        return Response(xml_wrapper(action, f"<vpc><vpcId>{vpc_id}</vpcId><state>available</state><cidrBlock>{state['vpcs'][vpc_id]['cidr']}</cidrBlock></vpc>"), mimetype='text/xml')

    elif action == "CreateSecurityGroup":
        sg_id = f"sg-{uuid.uuid4().hex[:8]}"
        state["security_groups"][sg_id] = {"vpc_id": request.form.get("VpcId"), "name": request.form.get("GroupName"), "desc": request.form.get("GroupDescription", "TF"), "ingress": [], "tags": {}}
        return Response(xml_wrapper(action, f"<groupId>{sg_id}</groupId>"), mimetype='text/xml')

    elif action == "CreateSubnet":
        s_id = f"subnet-{uuid.uuid4().hex[:8]}"
        state["subnets"][s_id] = {"vpc_id": request.form.get("VpcId"), "cidr": request.form.get("CidrBlock"), "tags": {}, "map_public_ip_on_launch": "false"}
        return Response(xml_wrapper(action, f"<subnet><subnetId>{s_id}</subnetId><state>available</state></subnet>"), mimetype='text/xml')

    elif action == "DeleteSubnet":
        target_id = request.form.get("SubnetId")
        if target_id in state["subnets"]: del state["subnets"][target_id]
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    elif action == "DeleteVpc":
        target_id = request.form.get("VpcId")
        if target_id in state["vpcs"]: del state["vpcs"][target_id]
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    elif action in ["RevokeSecurityGroupEgress", "AuthorizeSecurityGroupEgress", "AssociateRouteTable"]:
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    print(f"!!! 400 Bad Request: Action '{action}' not matched !!!")
    return Response(xml_wrapper(action, f"<Error><Code>InvalidAction</Code><Message>{action} not implemented</Message></Error>"), status=400, mimetype='text/xml')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=4566)