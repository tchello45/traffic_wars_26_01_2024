import iptc
import sys
#drop-ip
def block_ip(ip):
    rule = iptc.Rule()
    rule.src = ip
    rule.target = iptc.Target(rule, "DROP")
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.insert_rule(rule)
#accept-ip
def allow_ip(ip):
    rule = iptc.Rule()
    rule.src = ip
    rule.target = iptc.Target(rule, "ACCEPT")
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.insert_rule(rule)