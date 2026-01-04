from core import AWSResource

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
        self.vpc_id = vpc_id; self.cidr = cidr
        self.az = "us-east-1a"; self.available_ips = "251"
        self.map_public_ip = map_public_ip
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