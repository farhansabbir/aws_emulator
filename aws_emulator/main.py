from flask import Flask, request, Response
import uuid
from core import XML, RequestHelper
from backend import backend
from resources_vpc import SecurityGroup
from resources_gateways import InternetGateway, NatGateway, ElasticIP

app = Flask(__name__)

@app.route("/", methods=["POST"])
def endpoint():
    req = RequestHelper(request.form)
    action = req.get("Action")
    print(f"--> {action}")

    # --- IAM / STS ---
    if action == "GetCallerIdentity":
        xml = f"""<GetCallerIdentityResult><Arn>arn:aws:iam::{backend.account_id}:user/emulator</Arn><UserId>AIDACKCEVSQ6C2EXAMPLE</UserId><Account>{backend.account_id}</Account></GetCallerIdentityResult>"""
        return Response(XML.wrap(action, xml), mimetype="text/xml")
    if action == "GetUser":
        xml = f"""<GetUserResult><User><UserName>emulator</UserName><Arn>arn:aws:iam::{backend.account_id}:user/emulator</Arn></User></GetUserResult>"""
        return Response(XML.wrap(action, xml), mimetype="text/xml")
    if action == "ListRoles":
        return Response(XML.wrap(action, "<ListRolesResult><Roles/></ListRolesResult>"), mimetype="text/xml")

    # --- VPC ---
    if action == "CreateVpc":
        vpc = backend.create_vpc(req.get("CidrBlock"))
        return Response(XML.wrap(action, f"<vpc>{vpc.to_xml()}</vpc>"), mimetype="text/xml")
    
    if action == "DescribeVpcs":
        vid = req.get_filter("vpc-id")
        objs = [backend.vpcs[vid]] if vid and vid in backend.vpcs else list(backend.vpcs.values())
        return Response(XML.wrap(action, XML.dump_list("vpcSet", objs)), mimetype="text/xml")

    if action == "DescribeVpcAttribute":
        vpc_id = req.get("VpcId"); attr = req.get("Attribute")
        return Response(XML.wrap(action, f"<vpcId>{vpc_id}</vpcId><{attr}><value>true</value></{attr}>"), mimetype="text/xml")

    # --- Subnet ---
    if action == "CreateSubnet":
        sub = backend.create_subnet(req.get("VpcId"), req.get("CidrBlock"))
        return Response(XML.wrap(action, f"<subnet>{sub.to_xml()}</subnet>"), mimetype="text/xml")

    if action == "ModifySubnetAttribute":
        sid = req.get("SubnetId")
        if sid in backend.subnets:
            val = req.get("MapPublicIpOnLaunch.Value")
            if val: backend.subnets[sid].map_public_ip = val
        return Response(XML.wrap(action, "<return>true</return>"), mimetype="text/xml")

    if action == "DescribeSubnets":
        sid = req.get_filter("subnet-id"); vid = req.get_filter("vpc-id")
        objs = list(backend.subnets.values())
        if sid: objs = [o for o in objs if o.id == sid]
        if vid: objs = [o for o in objs if o.vpc_id == vid]
        return Response(XML.wrap(action, XML.dump_list("subnetSet", objs)), mimetype="text/xml")

    # --- Security Groups (FIXED FILTERING) ---
    if action == "CreateSecurityGroup":
        sg = SecurityGroup(req.get("VpcId"), req.get("GroupName"), req.get("GroupDescription"))
        backend.security_groups[sg.id] = sg
        return Response(XML.wrap(action, f"<groupId>{sg.id}</groupId>"), mimetype="text/xml")

    if action == "AuthorizeSecurityGroupIngress":
        gid = req.get("GroupId")
        if gid in backend.security_groups:
            backend.security_groups[gid].ingress.append({"p": req.get("IpPermissions.1.IpProtocol"), "f": req.get("IpPermissions.1.FromPort"), "t": req.get("IpPermissions.1.ToPort"), "c": req.get("IpPermissions.1.IpRanges.1.CidrIp")})
        return Response(XML.wrap(action, "<return>true</return>"), mimetype="text/xml")

    if action == "DescribeSecurityGroups":
        gid = req.get_filter("group-id")
        vid = req.get_filter("vpc-id")
        name = req.get_filter("group-name")
        
        objs = list(backend.security_groups.values())
        
        # Apply filters strictly
        if gid: objs = [o for o in objs if o.id == gid]
        if vid: objs = [o for o in objs if o.vpc_id == vid]
        if name: objs = [o for o in objs if o.name == name]
        
        return Response(XML.wrap(action, XML.dump_list("securityGroupInfo", objs)), mimetype="text/xml")

    # --- Network ACLs & Routes ---
    if action == "DescribeNetworkAcls":
        vid = req.get_filter("vpc-id"); objs = list(backend.nacls.values())
        if vid: objs = [o for o in objs if o.vpc_id == vid]
        return Response(XML.wrap(action, XML.dump_list("networkAclSet", objs)), mimetype="text/xml")

    if action == "DescribeRouteTables":
        vid = req.get_filter("vpc-id"); objs = list(backend.route_tables.values())
        if vid: objs = [o for o in objs if o.vpc_id == vid]
        return Response(XML.wrap(action, XML.dump_list("routeTableSet", objs)), mimetype="text/xml")

    # --- Instances ---
    if action == "RunInstances":
        sgs = req.get_list_prefix("SecurityGroupId.")
        inst = backend.run_instances(req.get("ImageId"), req.get("InstanceType"), req.get("SubnetId"), sgs)
        xml = f"""<reservationId>r-{uuid.uuid4().hex[:8]}</reservationId><ownerId>{backend.account_id}</ownerId><instancesSet><item>{inst.to_xml()}</item></instancesSet>"""
        return Response(XML.wrap(action, xml), mimetype="text/xml")

    if action == "DescribeInstances":
        iid = req.get_filter("instance-id")
        objs = [backend.instances[iid]] if iid and iid in backend.instances else list(backend.instances.values())
        res_xml = "".join([f"<item><reservationId>r-mock</reservationId><ownerId>{backend.account_id}</ownerId><instancesSet><item>{i.to_xml()}</item></instancesSet></item>" for i in objs])
        return Response(XML.wrap(action, f"<reservationSet>{res_xml}</reservationSet>"), mimetype="text/xml")

    if action == "DescribeInstanceTypes":
        req_type = req.get_filter("instance-type") or "t2.micro"
        xml = f"""<instanceTypeSet><item><instanceType>{req_type}</instanceType><processorInfo><supportedArchitectures><item>x86_64</item></supportedArchitectures></processorInfo><vCpuInfo><defaultVCpus>1</defaultVCpus></vCpuInfo><memoryInfo><sizeInMiB>1024</sizeInMiB></memoryInfo><instanceStorageSupported>false</instanceStorageSupported></item></instanceTypeSet>"""
        return Response(XML.wrap(action, xml), mimetype="text/xml")

    if action == "TerminateInstances":
        iid = req.get("InstanceId.1")
        if iid in backend.instances:
            backend.instances[iid].state_code = "48"; backend.instances[iid].state_name = "terminated"
        return Response(XML.wrap(action, f"<instancesSet><item><instanceId>{iid}</instanceId><currentState><code>48</code><name>terminated</name></currentState></item></instancesSet>"), mimetype="text/xml")

    if action == "StopInstances":
        iid = req.get("InstanceId.1")
        if iid in backend.instances:
            backend.instances[iid].state_code = "80"; backend.instances[iid].state_name = "stopped"
        return Response(XML.wrap(action, f"<instancesSet><item><instanceId>{iid}</instanceId><currentState><code>80</code><name>stopped</name></currentState><previousState><code>16</code><name>running</name></previousState></item></instancesSet>"), mimetype="text/xml")

    if action == "StartInstances":
        iid = req.get("InstanceId.1")
        if iid in backend.instances:
            backend.instances[iid].state_code = "16"; backend.instances[iid].state_name = "running"
        return Response(XML.wrap(action, f"<instancesSet><item><instanceId>{iid}</instanceId><currentState><code>16</code><name>running</name></currentState><previousState><code>80</code><name>stopped</name></previousState></item></instancesSet>"), mimetype="text/xml")

    if action == "DescribeInstanceAttribute":
        iid = req.get("InstanceId"); attr = req.get("Attribute")
        val = backend.instances[iid].attrs.get(attr, "true") if iid in backend.instances else "true"
        return Response(XML.wrap(action, f"<instanceId>{iid}</instanceId><{attr}><value>{val}</value></{attr}>"), mimetype="text/xml")

    if action == "ModifyInstanceAttribute":
        iid = req.get("InstanceId")
        if iid in backend.instances:
            if req.get("SourceDestCheck.Value"): backend.instances[iid].attrs["sourceDestCheck"] = req.get("SourceDestCheck.Value")
            if req.get("UserData.Value"): backend.instances[iid].attrs["userData"] = req.get("UserData.Value")
        return Response(XML.wrap(action, "<return>true</return>"), mimetype="text/xml")

    # --- Gateways & EIPs ---
    if action == "AllocateAddress":
        eip = ElasticIP(backend.pop_eip()); backend.eips[eip.id] = eip
        return Response(XML.wrap(action, f"<allocationId>{eip.id}</allocationId><publicIp>{eip.public_ip}</publicIp><domain>vpc</domain>"), mimetype="text/xml")

    if action == "DescribeAddresses":
        aid = req.get_filter("allocation-id")
        objs = [backend.eips[aid]] if aid and aid in backend.eips else list(backend.eips.values())
        return Response(XML.wrap(action, XML.dump_list("addressesSet", objs)), mimetype="text/xml")
    
    if action == "DescribeAddressesAttribute":
        aid = req.get("AllocationId") or req.get_filter("allocation-id")
        return Response(XML.wrap(action, f"<address><allocationId>{aid}</allocationId><domain>vpc</domain></address>"), mimetype="text/xml")

    if action == "CreateInternetGateway":
        igw = InternetGateway(); backend.igws[igw.id] = igw
        return Response(XML.wrap(action, f"<internetGateway>{igw.to_xml()}</internetGateway>"), mimetype="text/xml")

    if action == "AttachInternetGateway":
        igw = backend.igws.get(req.get("InternetGatewayId"))
        if igw: igw.attachments.append(req.get("VpcId"))
        return Response(XML.wrap(action, "<return>true</return>"), mimetype="text/xml")

    if action == "DescribeInternetGateways":
        gid = req.get_filter("internet-gateway-id")
        objs = [backend.igws[gid]] if gid and gid in backend.igws else list(backend.igws.values())
        return Response(XML.wrap(action, XML.dump_list("internetGatewaySet", objs)), mimetype="text/xml")

    if action == "CreateNatGateway":
        subnet_id = req.get("SubnetId"); alloc_id = req.get("AllocationId")
        eip = backend.eips.get(alloc_id)
        nat = NatGateway(subnet_id, alloc_id, backend.subnets[subnet_id].vpc_id, eip.public_ip if eip else "0.0.0.0")
        backend.natgws[nat.id] = nat
        return Response(XML.wrap(action, f"<natGateway>{nat.to_xml()}</natGateway>"), mimetype="text/xml")

    if action == "DescribeNatGateways":
        nid = req.get_filter("nat-gateway-id")
        objs = [backend.natgws[nid]] if nid and nid in backend.natgws else list(backend.natgws.values())
        return Response(XML.wrap(action, XML.dump_list("natGatewaySet", objs)), mimetype="text/xml")

    if action == "DeleteNatGateway":
        nid = req.get("NatGatewayId")
        if nid in backend.natgws: backend.natgws[nid].state = "deleted"
        return Response(XML.wrap(action, f"<natGatewayId>{nid}</natGatewayId>"), mimetype="text/xml")

    # --- Tags ---
    if action == "CreateTags":
        rid = req.get("ResourceId.1")
        res = backend.find_any(rid)
        if res: res.add_tags({req.get("Tag.1.Key"): req.get("Tag.1.Value")})
        return Response(XML.wrap(action, "<return>true</return>"), mimetype="text/xml")

    if action == "DescribeTags":
        rid = req.get_filter("resource-id"); items = ""
        if rid:
            res = backend.find_any(rid)
            if res: items = "".join([f"<item><resourceId>{rid}</resourceId><resourceType>res</resourceType><key>{k}</key><value>{v}</value></item>" for k,v in res.tags.items()])
        return Response(XML.wrap(action, f"<tagSet>{items}</tagSet>"), mimetype="text/xml")

    # --- Common Success Stubs ---
    if action in ["CreateRoute", "DeleteRoute", "AssociateRouteTable", "ModifyNetworkInterfaceAttribute", "DescribeLaunchTemplates", "DeleteVpc", "DeleteSubnet", "DeleteSecurityGroup", "DetachInternetGateway", "DeleteInternetGateway", "DeleteNatGateway", "ReleaseAddress", "RevokeSecurityGroupIngress", "DescribeNetworkInterfaces", "DescribeSecurityGroupRules", "RevokeSecurityGroupEgress", "AuthorizeSecurityGroupEgress"]:
        return Response(XML.wrap(action, "<return>true</return>"), mimetype="text/xml")

    print(f"!!! 400 Bad Request: Action '{action}' not matched !!!")
    return Response(XML.wrap("Error", "<Code>InvalidAction</Code>"), status=400, mimetype="text/xml")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=4566)