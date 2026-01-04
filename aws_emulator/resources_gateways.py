from core import AWSResource

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
        self.subnet_id = subnet_id; self.alloc_id = alloc_id
        self.vpc_id = vpc_id; self.public_ip = public_ip; self.state = "available"
    def to_xml(self):
        return f"""<natGatewayId>{self.id}</natGatewayId><subnetId>{self.subnet_id}</subnetId><vpcId>{self.vpc_id}</vpcId><state>{self.state}</state><natGatewayAddressSet><item><allocationId>{self.alloc_id}</allocationId><publicIp>{self.public_ip}</publicIp></item></natGatewayAddressSet>{self.render_tags()}"""