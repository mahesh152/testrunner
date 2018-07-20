import json
from decorator import decorator
from fabric.api import env, execute, parallel, run
import sys

details_file = sys.argv[0]

host = "ec2-{}.compute-1.amazonaws.com"
env.user = 'ec2-user'
env.key_filename = '/root/.ssh/couchbase-qe.pem'

with open(details_file, 'r') as f:
    data_store = json.load(f)

reservations = data_store["Reservations"]

ip_list_public = []
ip_list_private = []
ip_list_public_dns = []
for reservation in reservations:
    instances = reservation["Instances"]
    for instance in instances:
        tags = instance["Tags"]
        for tag in tags:
            if tag["Key"] == "aws:cloudformation:stack-name" and tag["Value"] == "a-test":
                if "PublicIpAddress" in instance:
                    ip_list_public.append(instance["PublicIpAddress"])
                    public_ip = instance["PublicIpAddress"].replace(".", "-")
                    ip_list_public_dns.append(host.format(public_ip))
                    ip_list_private.append(instance["PrivateIpAddress"])

print ip_list_public
print ip_list_public_dns
print ip_list_private

@decorator
def all_servers(task, *args, **kwargs):
    hosts = ip_list_public_dns
    return execute(parallel(task), *args, hosts=hosts, **kwargs)

@all_servers
def make_ssh_ready():
    run("echo 'couchbase' | sudo passwd --stdin root")
    run("sudo sed -i '/#PermitRootLogin yes/c\PermitRootLogin yes' /etc/ssh/sshd_config")
    run("sudo sed -i '/PermitRootLogin forced-commands-only/c\#PermitRootLogin "
        "forced-commands-only' /etc/ssh/sshd_config")
    run("sudo sed -i '/PasswordAuthentication no/c\PasswordAuthentication yes' "
        "/etc/ssh/sshd_config")
    run("sudo service sshd restart")

def make_ips_file():
    server_format = "\"{}\","
    with open("ips.txt", "w") as fp:
        for ip in ip_list_public:
            fp.write(server_format.format(ip))

make_ssh_ready()
make_ips_file()
