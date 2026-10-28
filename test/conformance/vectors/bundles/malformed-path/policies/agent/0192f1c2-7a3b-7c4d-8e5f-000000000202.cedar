@id("invoice-triage-tools")
permit (principal, action == WhiteTower::Action::"tool.invoke", resource)
when { [WhiteTower::Tool::"read_invoice", WhiteTower::Tool::"send_email"].contains(resource) };
