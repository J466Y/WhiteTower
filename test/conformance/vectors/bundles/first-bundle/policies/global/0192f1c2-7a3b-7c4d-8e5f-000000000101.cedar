@id("global-no-external-email")
forbid (principal, action == WhiteTower::Action::"tool.invoke", resource == WhiteTower::Tool::"send_email");
