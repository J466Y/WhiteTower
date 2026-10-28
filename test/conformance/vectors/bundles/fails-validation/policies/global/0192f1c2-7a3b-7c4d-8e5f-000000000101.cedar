@id("global-no-acme-tools")
forbid (principal, action == WhiteTower::Action::"tool.invoke", resource)
when { resource.vendor == "acme" };
