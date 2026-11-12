@id("invoice-triage-tools")
permit (principal, action == WhiteTower::Action::"tool.invoke", resource)
when { [WhiteTower::Tool::"agent/read_invoice", WhiteTower::Tool::"agent/send_email"].contains(resource) };
