from core import AWSResource

class NetworkInterface(AWSResource):
    def __init__(self, subnet_id, vpc_id, private_ip, groups, description=""):
        super().__init__("eni")
        self.subnet_id = subnet_id; self.vpc_id = vpc_id
        self.private_ip = private_ip; self.groups = groups
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