-- place this in lucidir/controller/admin/
module("luci.controller.admin.dns",package.seeall)

function index()
  entry({"admin","dns_sniff"},template("dns"),_("DNS_SNIFF"),50)
end