#!/bin/sh
# Sample implementation script to dump SPF info and add to PF tables
FILE=nospamd

mv $FILE $FILE.old
touch $FILE

### This first list are for domains who have SPF records.
for domain in \
        aol.com \
        apple.com \
        amazon.com \
	ebay.com \
        gmx.net \
        google.com \
        hotmail.com \
	livejournal.com \
	emailsrvr.com \
	twitter.com \
	cmail1.com \
	steampowered.com \
	metafilter.com \
	rackspace.com \
	startcom.org \
	github.com \
do
	echo "# $domain (SPF)" >> $FILE
	spf_dump.py $domain >> $FILE
done

# Add domains manually.
# echo "# localhost" >> $FILE
# echo "127.0.0.1" >> $FILE

pfctl -t $FILE -T replace -f $FILE 2>/dev/null
