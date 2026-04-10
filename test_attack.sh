#!/bin/bash
# Generates a fresh random IP every run — bypasses duplicate detection

RANDOM_IP="10.$(shuf -i 0-254 -n1).$(shuf -i 0-254 -n1).$(shuf -i 0-254 -n1)"
ATTACK=${1:-brute}

echo "Simulating $ATTACK attack from $RANDOM_IP"

case $ATTACK in
  brute)
    for i in {1..6}; do
      echo "$(date '+%b %e %H:%M:%S') server sshd[1234]: Failed password for admin from $RANDOM_IP port 22 ssh2" >> /var/log/auth.log
      sleep 0.2
    done
    ;;
  root)
    echo "$(date '+%b %e %H:%M:%S') server sshd[1234]: Failed password for root from $RANDOM_IP port 22 ssh2" >> /var/log/auth.log
    ;;
  invalid)
    for i in {1..4}; do
      echo "$(date '+%b %e %H:%M:%S') server sshd[1234]: Invalid user hacker from $RANDOM_IP port 4444" >> /var/log/auth.log
      sleep 0.3
    done
    ;;
  sudo)
    for i in {1..4}; do
      echo "$(date '+%b %e %H:%M:%S') server sudo[9999]: pam_unix(sudo:auth): authentication failure; user=www-data" >> /var/log/auth.log
      sleep 0.5
    done
    ;;
  reconnect)
    for i in {1..11}; do
      echo "$(date '+%b %e %H:%M:%S') server sshd[1234]: Received disconnect from $RANDOM_IP port 22: 11: Bye Bye" >> /var/log/auth.log
      sleep 0.1
    done
    ;;
  all)
    bash $0 brute &
    bash $0 root &
    bash $0 invalid &
    wait
    echo "All attack types fired."
    ;;
  *)
    echo "Usage: $0 brute|root|invalid|sudo|reconnect|all"
    ;;
esac

echo "Attack sent from $RANDOM_IP — watch main.py and Slack"
