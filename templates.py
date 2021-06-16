
dhcp_conf = """
option domain-name "gcc.ac.cn";
option domain-name-servers 114.114.114.114;
default-lease-time 600;
max-lease-time 7200;
ddns-update-style none;
include "/etc/dhcp/net.conf";
include "/etc/dhcp/vm.conf";
"""

dhcp_net_conf = """
subnet 192.168.20.0 netmask 255.255.255.192 {
        option subnet-mask 255.255.255.192;
        option routers 192.168.20.1;
        range 192.168.20.10 192.168.20.30;
        next-server 192.168.20.2;
        filename "2";
}
"""
dhcp_vm_conf = """
host 192.168.20.6 { hardware ethernet 02:45:d2:0a:85:57; fixed-address 192.168.20.6; }
host 192.168.20.7 { hardware ethernet 02:4d:f6:6e:d0:49; fixed-address 192.168.20.7; }
host 192.168.20.8 { hardware ethernet 02:0b:ad:3d:8b:6e; fixed-address 192.168.20.8; }
host 192.168.20.9 { hardware ethernet 02:de:a4:d5:03:68; fixed-address 192.168.20.9; }
"""
ovs_xml = """
<network>
  <name>ovs</name>
  <uuid>c4b321c3-ab75-4232-bb1f-ca4f92881d77</uuid>
  <forward mode='bridge'/>
  <bridge name='br0'/>
  <virtualport type='openvswitch'/>
</network>
"""
