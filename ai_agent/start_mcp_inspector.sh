cd ~/VSCode/angr/angr_ctf
npx @modelcontextprotocol/inspector docker attach $(docker ps -q --filter ancestor=angr-ctf:latest) &
cd -
