@id("global-no-external-email")
forbid (principal, action == WhiteTower::Action::"tool.invoke", resource == WhiteTower::Tool::"agent/send_email");
