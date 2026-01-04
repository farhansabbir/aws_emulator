from flask import Flask, request, Response
import uuid
import datetime

app = Flask(__name__)

# ==========================================
# 1. CORE FRAMEWORK
# ==========================================

class XML:
    @staticmethod
    def wrap(action, content):
        req_id = str(uuid.uuid4())
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <{action}Response xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
            {content}
            <requestId>{req_id}</requestId>
        </{action}Response>"""

    @staticmethod
    def dump_list(wrapper_name, item_list):
        items = "".join([f"<item>{x.to_xml()}</item>" for x in item_list])
        return f"<{wrapper_name}>{items}</{wrapper_name}>"

class RequestHelper:
    def __init__(self, form_data):
        self.data = form_data

    def get(self, name, default=None):
        return self.data.get(name, default)

    def get_list_prefix(self, prefix):
        items = []
        for k, v in self.data.items():
            if k.startswith(prefix) and "." in k:
                items.append(v)
        return items

    def get_filter(self, name):
        for k, v in self.data.items():
            if v == name and k.startswith("Filter.") and k.endswith(".Name"):
                idx = k.split('.')[1] 
                return self.data.get(f"Filter.{idx}.Value.1")
        
        direct_map = {
            'vpc-id': 'VpcId.1', 'subnet-id': 'SubnetId.1', 
            'group-id': 'GroupId.1', 'instance-id': 'InstanceId.1',
            'allocation-id': 'AllocationId.1', 'network-interface-id': 'NetworkInterfaceId.1',
            'internet-gateway-id': 'InternetGatewayId.1', 'nat-gateway-id': 'NatGatewayId.1',
            'instance-type': 'InstanceType.1'
        }
        return self.data.get(direct_map.get(name))

# ==========================================
# 2. RESOURCE MODELS
# ==========================================

class AWSResource:
    def __init__(self, resource_type):
        self.id = f"{resource_type}-{uuid.uuid4().hex[:8]}"
        self.tags = {}
        self.created_at = datetime.datetime.utcnow().isoformat() + "Z"

    def to_xml(self): raise NotImplementedError
    def add_tags(self, tag_dict): self.tags.update(tag_dict)
    def render_tags(self):
        if not self.tags: return ""
        items = "".join([f"<item><key>{k}</key><value>{v}</value></item>" for k, v in self.tags.items()])
        return f"<tagSet>{items}</tagSet>"

class Vpc(AWSResource):
    def __init__(self, cidr):
        super().__init__("vpc")
        self.cidr = cidr; self.state = "available"; self.is_default = "false"
        self.dhcp_opts = "dopt-default"; self.tenancy = "default"
    def to_xml(self):
        return f"""<vpcId>{self.id}</vpcId><state>{self.state}</state><cidrBlock>{self.cidr}</cidrBlock><dhcpOptionsId>{self.dhcp_opts}</dhcpOptionsId><instanceTenancy>{self.tenancy}</instanceTenancy><isDefault>{self.is_default}</isDefault>{self.render_tags()}"""

class Subnet(AWSResource):
    def __init__(self, vpc_id, cidr, map_public_ip="false"):
        super().__init__("subnet")
        self.vpc_id = vpc_id
        self.cidr = cidr
        self.az = "us-east-1a"
        self.map_public_ip = map_public_ip
        self.available_ips = "251"
    def to_xml(self):
        return f"""<subnetId>{self.id}</subnetId><vpcId>{self.vpc_id}</vpcId><cidrBlock>{self.cidr}</cidrBlock><availabilityZone>{self.az}</availabilityZone><availableIpAddressCount>{self.available_ips}</availableIpAddressCount><state>available</state><mapPublicIpOnLaunch>{self.map_public_ip}</mapPublicIpOnLaunch>{self.render_tags()}"""

class SecurityGroup(AWSResource):
    def __init__(self, vpc_id, name, desc):
        super().__init__("sg")
        self.vpc_id = vpc_id; self.name = name; self.desc = desc; self.ingress = []
    def to_xml(self):
        perms = "".join([f"<item><ipProtocol>{r['p']}</ipProtocol><fromPort>{r['f']}</fromPort><toPort>{r['t']}</toPort><ipRanges><item><cidrIp>{r['c']}</cidrIp></item></ipRanges></item>" for r in self.ingress])
        return f"""<groupId>{self.id}</groupId><groupName>{self.name}</groupName><groupDescription>{self.desc}</groupDescription><vpcId>{self.vpc_id}</vpcId><ownerId>123456789012</ownerId><ipPermissions>{perms}</ipPermissions><ipPermissionsEgress/>{self.render_tags()}"""

class NetworkAcl(AWSResource):
    def __init__(self, vpc_id, is_default="false"):
        super().__init__("acl")
        self.vpc_id = vpc_id; self.is_default = is_default
    def to_xml(self):
        entry = f"<item><ruleNumber>100</ruleNumber><protocol>-1</protocol><ruleAction>allow</ruleAction><egress>false</egress><cidrBlock>0.0.0.0/0</cidrBlock></item>"
        entry += f"<item><ruleNumber>100</ruleNumber><protocol>-1</protocol><ruleAction>allow</ruleAction><egress>true</egress><cidrBlock>0.0.0.0/0</cidrBlock></item>"
        return f"""<networkAclId>{self.id}</networkAclId><vpcId>{self.vpc_id}</vpcId><default>{self.is_default}</default><entrySet>{entry}</entrySet>{self.render_tags()}"""

class RouteTable(AWSResource):
    def __init__(self, vpc_id, is_main="false"):
        super().__init__("rtb")
        self.vpc_id = vpc_id; self.is_main = is_main
        self.routes = [] 
    def to_xml(self):
        routes_xml = f"<item><destinationCidrBlock>10.0.0.0/16</destinationCidrBlock><gatewayId>local</gatewayId><state>active</state><origin>CreateRouteTable</origin></item>"
        assoc_xml = f"<item><routeTableAssociationId>rtbassoc-default</routeTableAssociationId><routeTableId>{self.id}</routeTableId><main>{self.is_main}</main></item>"
        return f"""<routeTableId>{self.id}</routeTableId><vpcId>{self.vpc_id}</vpcId><routeSet>{routes_xml}</routeSet><associationSet>{assoc_xml}</associationSet>{self.render_tags()}"""

class NetworkInterface(AWSResource):
    def __init__(self, subnet_id, vpc_id, private_ip, groups, description=""):
        super().__init__("eni")
        self.subnet_id = subnet_id; self.vpc_id = vpc_id; self.private_ip = private_ip; self.groups = groups
        self.description = description; self.public_ip = None; self.attachment = None
    def to_xml(self):
        sg_xml = "".join([f"<item><groupId>{gid}</groupId><groupName>default</groupName></item>" for gid in self.groups])
        assoc_xml = f"<association><publicIp>{self.public_ip}</publicIp><ipOwnerId>amazon</ipOwnerId></association>" if self.public_ip else ""
        attach_xml = f"<attachment><attachmentId>eni-attach-0</attachmentId><instanceId>{self.attachment['instance_id']}</instanceId><deviceIndex>0</deviceIndex><status>attached</status><attachTime>{self.created_at}</attachTime><deleteOnTermination>true</deleteOnTermination></attachment>" if self.attachment else ""
        return f"""<networkInterfaceId>{self.id}</networkInterfaceId><subnetId>{self.subnet_id}</subnetId><vpcId>{self.vpc_id}</vpcId><description>{self.description}</description><status>in-use</status><privateIpAddress>{self.private_ip}</privateIpAddress><groupSet>{sg_xml}</groupSet><sourceDestCheck>true</sourceDestCheck>{assoc_xml}{attach_xml}{self.render_tags()}"""

class Instance(AWSResource):
    def __init__(self, image_id, flavor, eni):
        super().__init__("i")
        self.image_id = image_id; self.flavor = flavor; self.eni = eni
        self.state_code = "16"; self.state_name = "running"
        self.attrs = {"disableApiTermination": "false", "instanceInitiatedShutdownBehavior": "stop", "sourceDestCheck": "true"}
    def to_xml(self):
        pub_ip_tag = f"<ipAddress>{self.eni.public_ip}</ipAddress>" if self.eni.public_ip else ""
        return f"""<instanceId>{self.id}</instanceId><imageId>{self.image_id}</imageId><instanceState><code>{self.state_code}</code><name>{self.state_name}</name></instanceState><privateIpAddress>{self.eni.private_ip}</privateIpAddress>{pub_ip_tag}<vpcId>{self.eni.vpc_id}</vpcId><subnetId>{self.eni.subnet_id}</subnetId><instanceType>{self.flavor}</instanceType><networkInterfaceSet><item>{self.eni.to_xml()}</item></networkInterfaceSet>{self.render_tags()}"""

class ElasticIP(AWSResource):
    def __init__(self, ip):
        super().__init__("eipalloc")
        self.public_ip = ip; self.domain = "vpc"
    def to_xml(self):
        return f"""<allocationId>{self.id}</allocationId><publicIp>{self.public_ip}</publicIp><domain>{self.domain}</domain>{self.render_tags()}"""

class InternetGateway(AWSResource):
    def __init__(self):
        super().__init__("igw")
        self.attachments = []
    def to_xml(self):
        attach_xml = "".join([f"<item><vpcId>{vpc}</vpcId><state>available</state></item>" for vpc in self.attachments])
        return f"""<internetGatewayId>{self.id}</internetGatewayId><attachmentSet>{attach_xml}</attachmentSet>{self.render_tags()}"""

class NatGateway(AWSResource):
    def __init__(self, subnet_id, alloc_id, vpc_id, public_ip):
        super().__init__("nat")
        self.subnet_id = subnet_id; self.alloc_id = alloc_id; self.vpc_id = vpc_id; self.public_ip = public_ip; self.state = "available"
    def to_xml(self):
        return f"""<natGatewayId>{self.id}</natGatewayId><subnetId>{self.subnet_id}</subnetId><vpcId>{self.vpc_id}</vpcId><state>{self.state}</state><natGatewayAddressSet><item><allocationId>{self.alloc_id}</allocationId><publicIp>{self.public_ip}</publicIp></item></natGatewayAddressSet>{self.render_tags()}"""

# ==========================================
# 3. BACKEND SERVICE
# ==========================================

class EC2Backend:
    def __init__(self):
        self.vpcs = {}; self.subnets = {}; self.security_groups = {}; self.enis = {}
        self.instances = {}; self.igws = {}; self.natgws = {}; self.eips = {}
        self.nacls = {}; self.route_tables = {}
        self.ip_pool = [f"203.0.113.{i}" for i in range(1, 101)]
        self.eip_pool = [f"52.99.100.{i}" for i in range(1, 51)]
        self.account_id = "123456789012"

    def pop_public_ip(self): return self.ip_pool.pop(0) if self.ip_pool else "0.0.0.0"
    def pop_eip(self): return self.eip_pool.pop(0) if self.eip_pool else "0.0.0.0"

    def create_vpc(self, cidr):
        vpc = Vpc(cidr); self.vpcs[vpc.id] = vpc
        sg = SecurityGroup(vpc.id, "default", "default VPC security group"); self.security_groups[sg.id] = sg
        acl = NetworkAcl(vpc.id, is_default="true"); self.nacls[acl.id] = acl
        rtb = RouteTable(vpc.id, is_main="true"); self.route_tables[rtb.id] = rtb
        return vpc

    def create_subnet(self, vpc_id, cidr):
        s = Subnet(vpc_id, cidr); self.subnets[s.id] = s; return s

    def run_instances(self, image_id, flavor, subnet_id, sg_ids):
        subnet = self.subnets[subnet_id]
        private_ip = f"10.0.1.{len(self.instances)+10}"
        public_ip = self.pop_public_ip() if subnet.map_public_ip == "true" else None
        eni = NetworkInterface(subnet_id, subnet.vpc_id, private_ip, sg_ids)
        eni.public_ip = public_ip
        self.enis[eni.id] = eni
        inst = Instance(image_id, flavor, eni); self.instances[inst.id] = inst
        eni.attachment = {"instance_id": inst.id, "device_index": 0}
        return inst

    def find_any(self, res_id):
        for m in [self.vpcs, self.subnets, self.security_groups, self.enis, self.instances, self.igws, self.natgws, self.eips, self.nacls, self.route_tables]:
            if res_id in m: return m[res_id]
        return None

backend = EC2Backend()

# ==========================================
# 4. FLASK ROUTES
# ==========================================

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

    # --- Security Groups ---
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
        objs = [backend.security_groups[gid]] if gid and gid in backend.security_groups else list(backend.security_groups.values())
        return Response(XML.wrap(action, XML.dump_list("securityGroupInfo", objs)), mimetype="text/xml")

    # --- Network ACLs & Routes ---
    if action == "DescribeNetworkAcls":
        vid = req.get_filter("vpc-id")
        objs = list(backend.nacls.values())
        if vid: objs = [o for o in objs if o.vpc_id == vid]
        return Response(XML.wrap(action, XML.dump_list("networkAclSet", objs)), mimetype="text/xml")

    if action == "DescribeRouteTables":
        vid = req.get_filter("vpc-id")
        objs = list(backend.route_tables.values())
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

    # THE FIX: ADDED DEDICATED HANDLER FOR DescribeInstanceTypes
    if action == "DescribeInstanceTypes":
        req_type = req.get_filter("instance-type") or "t2.micro"
        xml = f"""<instanceTypeSet><item><instanceType>{req_type}</instanceType><processorInfo><supportedArchitectures><item>x86_64</item></supportedArchitectures></processorInfo><vCpuInfo><defaultVCpus>1</defaultVCpus></vCpuInfo><memoryInfo><sizeInMiB>1024</sizeInMiB></memoryInfo><instanceStorageSupported>false</instanceStorageSupported></item></instanceTypeSet>"""
        return Response(XML.wrap(action, xml), mimetype="text/xml")

    if action == "TerminateInstances":
        iid = req.get("InstanceId.1")
        if iid in backend.instances:
            backend.instances[iid].state_code = "48"; backend.instances[iid].state_name = "terminated"
        return Response(XML.wrap(action, f"<instancesSet><item><instanceId>{iid}</instanceId><currentState><code>48</code><name>terminated</name></currentState></item></instancesSet>"), mimetype="text/xml")

    if action == "DescribeInstanceAttribute":
        iid = req.get("InstanceId"); attr = req.get("Attribute")
        val = backend.instances[iid].attrs.get(attr, "true") if iid in backend.instances else "true"
        return Response(XML.wrap(action, f"<instanceId>{iid}</instanceId><{attr}><value>{val}</value></{attr}>"), mimetype="text/xml")

    if action == "ModifyInstanceAttribute":
        iid = req.get("InstanceId")
        if iid in backend.instances:
            if req.get("SourceDestCheck.Value"): backend.instances[iid].attrs["sourceDestCheck"] = req.get("SourceDestCheck.Value")
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