from resources_vpc import Vpc, Subnet, SecurityGroup, NetworkAcl, RouteTable
from resources_ec2 import Instance, NetworkInterface
from resources_gateways import ElasticIP, InternetGateway, NatGateway

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

# Global Singleton
backend = EC2Backend()