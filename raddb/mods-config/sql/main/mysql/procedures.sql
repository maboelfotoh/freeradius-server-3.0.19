delimiter //

/*
#######################################################################
# NAS Query
#######################################################################
# This query retrieves the radius clients
#
# 0. Row ID (currently unused)
# 1. Name (or IP address)
# 2. Shortname
# 3. Type
# 4. Secret
# 5. Server
#######################################################################
*/

create procedure getClients()
begin
	SELECT id, nasname, shortname, type, secret, server \
	FROM nas;
end //

/*
#######################################################################
# Authorization Queries
#######################################################################
# These queries compare the check items for the user
# in radcheck and setup the reply items in
# radreply. You can use any query/tables
# you want, but the return data for each row MUST
# be in the following order:
#
# 0. Row ID (currently unused)
# 1. UserName/GroupName
# 2. Item Attr Name
# 3. Item Attr Value
# 4. Item Attr Operation
#######################################################################
*/

create procedure authorizeCheck(username varchar(64))
begin
	SELECT id, username, attribute, value, op \
	FROM radcheck \
	WHERE radcheck.username = username \
	ORDER BY id;
end //
create procedure authorizeReply(username varchar(64))
begin
	SELECT id, username, attribute, value, op \
	FROM radreply \
	WHERE radreply.username = username \
	ORDER BY id;
end //
create procedure authorizeGroupMembership(username varchar(64))
begin
	SELECT groupname \
	FROM radusergroup \
	WHERE radusergroup.username = username \
	ORDER BY priority;
end //
create procedure authorizeGroupCheck(groupname varchar(64))
begin
	SELECT id, groupname, attribute, \
	Value, op \
	FROM radgroupcheck \
	WHERE radgroupcheck.groupname = groupname \
	ORDER BY id;
end //
create procedure authorizeGroupReply(groupname varchar(64))
begin
	SELECT id, groupname, attribute, \
	value, op \
	FROM radgroupreply \
	WHERE radgroupreply.groupname = groupname \
	ORDER BY id;
end //
create procedure simulCount(username varchar(64))
begin
	SELECT COUNT(*) \
	FROM radacct \
	WHERE radacct.username = username \
	AND acctstoptime IS NULL;
end //
create procedure simulVerify(username varchar(64))
begin
	SELECT \
		radacctid, acctsessionid, username, nasipaddress, nasportid, framedipaddress, \
		callingstationid, framedprotocol \
	FROM radacct \
	WHERE radacct.username = username \
	AND acctstoptime IS NULL;
end //



/*
accounting-on

#
#  Bulk terminate all sessions associated with a given NAS
#

*/
create procedure nasSessionsTerminate(eventTimestamp int(12) unsigned,
				acctterminatecause varchar(32),
				nasipaddress varchar(15))
begin
	UPDATE radacct \
	SET \
		radacct.acctstoptime = FROM_UNIXTIME(\
			eventTimestamp), \
		radacct.acctsessiontime	= eventTimestamp \
			- UNIX_TIMESTAMP(acctstarttime), \
		radacct.acctterminatecause = acctterminatecause \
	WHERE radacct.acctstoptime IS NULL \
	AND radacct.nasipaddress   = nasipaddress \
	AND radacct.acctstarttime <= FROM_UNIXTIME(\
		eventTimestamp);
end //




/*
post-auth
*/

/*
#
#  Implement the "sql_session_start" policy.
#  See raddb/policy.d/accounting for more details.
#
#  You also need to fix the other queries as
#  documented below.  Look for "sql_session_start".
#
*/
create procedure postAuth(acctsessionid varchar(64),
			acctuniquesessionid varchar(32),
			username varchar(64),
			realm varchar(64),
			nasipaddress varchar(15),
			nasportid varchar(15),
			nasporttype varchar(32),
			eventTimestamp int(12) unsigned,
			connectinfo varchar(50),
			calledstationid varchar(50),
			callingstationid varchar(50),
			servicetype varchar(32))
begin
	INSERT INTO radacct \
		(		acctsessionid,		acctuniqueid,		username, \
		realm,			nasipaddress,		nasportid, \
		nasporttype,		acctstarttime,		acctupdatetime, \
		acctstoptime,		acctsessiontime, 	acctauthentic, \
		connectinfo_start,	connectinfo_stop, 	acctinputoctets, \
		acctoutputoctets,	calledstationid, 	callingstationid, \
		acctterminatecause,	servicetype,		framedprotocol, \
		framedipaddress,	framedipv6address,	framedipv6prefix, \
		framedinterfaceid,	delegatedipv6prefix) \
	VALUES(\
		acctsessionid, \
		acctuniquesessionid, \
		username, \
		realm, \
		nasipaddress, \
		NULLIF(nasportid, ''), \
		nasporttype, \
		FROM_UNIXTIME(eventTimestamp), \
		NULL, \
		NULL, \
		0, \
		'', \
		connectinfo, \
		NULL, \
		0, \
		0, \
		calledstationid, \
		callingstationid, \
		NULL, \
		servicetype, \
		NULL, \
		'', \
		'', \
		'', \
		'', \
		'');
end //


create procedure postAuth2(eventTimestamp int(12) unsigned,
			connectinfo varchar(50),
			acctsessionid varchar(64),
			username varchar(64),
			nasipaddress varchar(15),
			nasportid varchar(15),
			nasporttype varchar(32))
begin
	UPDATE radacct SET \
		radacct.AcctStartTime = FROM_UNIXTIME(eventTimestamp), \
		radacct.AcctUpdateTime = FROM_UNIXTIME(eventTimestamp), \
		radacct.ConnectInfo_start = connectinfo, \
		radacct.AcctSessionId = acctsessionid \
	WHERE radacct.UserName = username \
		AND radacct.NASIPAddress = nasipaddress \
		AND radacct.NASPortId = nasportid \
		AND radacct.NASPortType = nasporttype \
		AND radacct.AcctStopTime IS NULL;
end //



/*
start
*/

/*
#
#  Insert a new record into the sessions table
#
*/
create procedure sessionInsert(acctsessiondid varchar(64),
				acctuniquesessionid varchar(32),
				username varchar(64),
				realm varchar(64),
				nasipaddress varchar(15),
				nasportid varchar(15),
				nasporttype varchar(32),
				eventtimestamp int(12) unsigned,
				acctauthentic varchar(32),
				connectinfo varchar(50),
				calledstationid varchar(50),
				callingstationid varchar(50),
				servicetype varchar(32),
				framedprotocol varchar(32),
				framedipaddress varchar(15),
				framedipv6address varchar(45),
				framedipv6prefix varchar(45),
				framedinterfaceid varchar(44),
				delegatedipv6prefix varchar(45))
begin
	INSERT INTO radacct \
		(		acctsessionid,		acctuniqueid,		username, \
		realm,			nasipaddress,		nasportid, \
		nasporttype,		acctstarttime,		acctupdatetime, \
		acctstoptime,		acctsessiontime, 	acctauthentic, \
		connectinfo_start,	connectinfo_stop, 	acctinputoctets, \
		acctoutputoctets,	calledstationid, 	callingstationid, \
		acctterminatecause,	servicetype,		framedprotocol, \
		framedipaddress,	framedipv6address,	framedipv6prefix, \
		framedinterfaceid,	delegatedipv6prefix) \
	VALUES \
		(acctsessionid, \
		acctuniquesessionid, \
		username, \
		realm, \
		nasipaddress, \
		nasportid, \
		nasporttype, \
		FROM_UNIXTIME(eventTimestamp), \
		FROM_UNIXTIME(eventTimestamp), \
		NULL, \
		'0', \
		accauthentic, \
		connectinfo, \
		'', \
		'0', \
		'0', \
		calledstationid, \
		callingstationid, \
		'', \
		servicetype, \
		framedprotocol, \
		framedipaddress, \
		framedipv6address, \
		framedipv6prefix, \
		framedinterfaceid, \
		delegatedipv6prefix);
end //

/*
#
#  When using "sql_session_start", you should comment out
#  the previous query, and enable this one.
#
#  Just change the previous query to "-query",
#  and this one to "query".  The previous one
#  will be ignored, and this one will be
#  enabled.
#
*/
create procedure sqlSessionInsert(acctsessionid varchar(64),
				acctuniquesessionid varchar(32),
				acctauthentic varchar(32),
				connectinfo varchar(50),
				servicetype varchar(32),
				framedprotocol varchar(32),
				framedipaddress varchar(15),
				framedipv6address varchar(45),
				framedipv6prefix varchar(45),
				framedinterfaceid varchar(44),
				delegatedipv6prefix varchar(45),
				eventTimestamp int(12) unsigned,
				username varchar(64),
				nasipaddress varchar(15),
				nasportid varchar(15),
				nasporttype varchar(32))
begin
	UPDATE radacct \
	SET \
		radacct.AcctSessionId = acctsessionid, \
		radacct.AcctUniqueId = acctuniquesessionid, \
		radacct.AcctAuthentic = acctauthentic, \
		radacct.ConnectInfo_start = connectinfo, \
		radacct.ServiceType = servicetype, \
		radacct.FramedProtocol = framedprotocol, \
		radacct.framedipaddress = framedipaddress, \
		radacct.framedipv6address = framedipv6address, \
		radacct.framedipv6prefix = framedipv6prefix, \
		radacct.framedinterfaceid = framedinterfaceid, \
		radacct.delegatedipv6prefix = delegatedipv6prefix, \
		radacct.AcctStartTime = FROM_UNIXTIME(eventTimestamp), \
		radacct.AcctUpdateTime = FROM_UNIXTIME(eventTimestamp) \
	WHERE radacct.UserName = username \
		AND radacct.NASIPAddress = nasipaddress \
		AND radacct.NASPortId = nasportid \
		AND radacct.NASPortType = nasporttype \
		AND radacct.AcctStopTime IS NULL;
end //

/*
#
#  Key constraints prevented us from inserting a new session,
#  use the alternate query to update an existing session.
#
*/
create procedure sqlAlternateSessionInsert(eventTimestamp int(12) unsigned,
					connectinfo varchar(50),
					acctuniquesessionid varchar(32))
begin
	UPDATE radacct SET \
		radacct.acctstarttime = FROM_UNIXTIME(eventTimestamp), \
		radacct.acctupdatetime = FROM_UNIXTIME(eventTimestamp), \
		radacct.connectinfo_start = connectinfo \
	WHERE radacct.AcctUniqueId = acctuniquesessionid;
end //

/*
interim-update
*/

/*
#
#  Update an existing session and calculate the interval
#  between the last data we received for the session and this
#  update. This can be used to find stale sessions.
#
*/
create procedure sessionUpdate(eventTimestamp int(12) unsigned,
				framedipaddress varchar(15),
				framedipv6address varchar(45),
				framedipv6prefix varchar(45),
				framedinterfaceid varchar(44),
				delegatedipv6prefix varchar(45),
				acctsessiontime int(12),
				acctinputoctets bigint,
				acctouputoctets bigint,
				acctuniquesessionid varchar(32))
begin
	UPDATE radacct \
	SET \
		radacct.acctupdatetime  = (@acctupdatetime_old:=acctupdatetime), \
		radacct.acctupdatetime  = FROM_UNIXTIME(eventTimestamp), \
		radacct.acctinterval    = eventTimestamp - \
			UNIX_TIMESTAMP(@acctupdatetime_old), \
		radacct.framedipaddress = framedipaddress, \
		radacct.framedipv6address = framedipv6address, \
		radacct.framedipv6prefix = framedipv6prefix, \
		radacct.framedinterfaceid = framedinterfaceid, \
		radacct.delegatedipv6prefix = delegatedipv6prefix, \
		radacct.acctsessiontime = acctsessiontime, \
		radacct.acctinputoctets = acctinputoctets, \
		radacct.acctoutputoctets = acctoutputoctets \
	WHERE radacct.AcctUniqueId = acctuniquesessionid;
end //

/*
#
#  The update condition matched no existing sessions. Use
#  the values provided in the update to create a new session.
#
*/
create procedure interimUpdateNewSession(
				acctsessionid varchar(64),
				acctuniquesessionid varchar(32),
				username varchar(64),
				realm varchar(64),
				nasipaddress varchar(15),
				nasportid varchar(15),
				nasporttype varchar(32),
				eventTimestamp int(12) unsigned,
				acctsessiontime1 int(12),
				acctsessiontime2 int(12),
				acctauthentic varchar(32),
				connectinfo varchar(50),				
				acctinputoctets bigint,
				acctoutputoctets bigint,
				calledstationid varchar(50),
				callingstationid varchar(50),
				servicetype varchar(32),
				framedprotocol varchar(32),
				framedipaddress varchar(15),
				framedipv6address varchar(45),
				framedipv6prefix varchar(45),
				framedinterfaceid varchar(44),
				delegatedipv6prefix varchar(45))
begin
	INSERT INTO radacct \
		(		acctsessionid,		acctuniqueid,		username, \
		realm,			nasipaddress,		nasportid, \
		nasporttype,		acctstarttime,		acctupdatetime, \
		acctstoptime,		acctsessiontime, 	acctauthentic, \
		connectinfo_start,	connectinfo_stop, 	acctinputoctets, \
		acctoutputoctets,	calledstationid, 	callingstationid, \
		acctterminatecause,	servicetype,		framedprotocol, \
		framedipaddress,	framedipv6address,	framedipv6prefix, \
		framedinterfaceid,	delegatedipv6prefix) \
	VALUES \
		(acctsessionid, \
		acctuniquesessionid, \
		username, \
		realm, \
		nasipaddress, \
		nasportid, \
		nasporttype, \
		FROM_UNIXTIME(eventTimestamp - acctsessiontime1), \
		FROM_UNIXTIME(eventTimestamp), \
		NULL, \
		acctsessiontime2, \
		acctauthentic, \
		connectinfo, \
		'', \
		acctinputoctets, \
		acctoutputoctets, \
		calledstationid, \
		callingstationid, \
		'', \
		servicetype, \
		framedprotocol, \
		framedipaddress, \
		framedipv6address, \
		framedipv6prefix, \
		framedinterfaceid, \
		delegatedipv6prefix);
end //

/*
#
#  When using "sql_session_start", you should comment out
#  the previous query, and enable this one.
#
#  Just change the previous query to "-query",
#  and this one to "query".  The previous one
#  will be ignored, and this one will be
#  enabled.
#
*/
create procedure interimUpdate(acctsessionid varchar(64),
				acctuniquesessionid varchar(32),
				acctauthentic varchar(32),
				connectinfo varchar(50),
				servicetype varchar(32),
				framedprotocol varchar(32),
				framedipaddress varchar(15),
				framedipv6address varchar(45),
				framedipv6prefix varchar(45),
				framedinterfaceid varchar(44),
				delegatedipv6prefix varchar(45),
				eventTimestamp int(12) unsigned,
				acctsessiontime int(12),
				acctinputoctets bigint,
				acctoutputoctets bigint,
				username varchar(64),
				nasipaddress varchar(15),
				nasportid varchar(15),
				nasporttype varchar(32))
begin
	UPDATE radacct \
	SET \
		radacct.AcctSessionId = acctsessionid, \
		radacct.AcctUniqueId = acctuniquesessionid, \
		radacct.AcctAuthentic = acctauthentic, \
		radacct.ConnectInfo_start = connectinfo, \
		radacct.ServiceType = servicetype, \
		radacct.FramedProtocol = framedprotocol, \
		radacct.framedipaddress = framedipaddress, \
		radacct.framedipv6address = framedipv6address, \
		radacct.framedipv6prefix = framedipv6prefix, \
		radacct.framedinterfaceid = framedinterfaceid, \
		radacct.delegatedipv6prefix = delegatedipv6prefix, \
		radacct.AcctUpdateTime = FROM_UNIXTIME(eventTimestamp), \
		radacct.AcctSessionTime = acctsessiontime, \
		radacct.AcctInputOctets = acctinputoctets, \
		radacct.AcctOutputOctets = acctoutputoctets \
	WHERE radacct.UserName = username \
		AND radacct.NASIPAddress = nasipaddress \
		AND radacct.NASPortId = nasportid \
		AND radacct.NASPortType = nasporttype \
		AND radacct.AcctStopTime IS NULL;
end //

/*
Stop
*/

/*
#
#  Session has terminated, update the stop time and statistics.
#
*/
create procedure stopInfoUpdate(eventTimestamp int(12) unsigned,
				acctsessiontime int(12),
				acctinputoctets bigint,
				acctoutputoctets bigint,
				acctterminatecause varchar(32),
				connectinfo varchar(50),
				acctuniquesessionid varchar(32))
begin
	UPDATE radacct SET \
		radacct.acctstoptime	= FROM_UNIXTIME(eventTimestamp), \
		radacct.acctsessiontime = acctsessiontime, \
		radacct.acctinputoctets = acctinputoctents, \
		radacct.acctoutputoctets = acctoutputoctets, \
		radacct.acctterminatecause = acctterminatecause, \
		radacct.connectinfo_stop = connectinfo \
	WHERE radacct.AcctUniqueId = acctuniquesessionid;
end //

/*
#
#  The update condition matched no existing sessions. Use
#  the values provided in the update to create a new session.
#
*/
create procedure stop2(acctsessionid varchar(64),
			acctuniqueid varchar(32),
			username varchar(64),
			realm varchar(64),
			nasipaddress varchar(15),
			nasportid varchar(15),
			nasporttype varchar(32),
			eventTimestamp int(12) unsigned,
			acctsessiontime1 int(12),
			acctsessiontime2 int(12),
			acctauthentic varchar(32),
			connectinfo varchar(50),
			acctinputoctets bigint,
			acctoutputoctets bigint,
			calledstationid varchar(50),
			callingstationid varchar(50),
			acctterminatecause varchar(32),
			servicetype varchar(32),
			framedprotocol varchar(32),
			framedipaddress varchar(15),
			framedipv6address varchar(45),
			framedipv6prefix varchar(45),
			framedinterfaceid varchar(44),
			delegatedipv6prefix varchar(45))		
begin
	INSERT INTO radacct \
		(		acctsessionid,		acctuniqueid,		username, \
		realm,			nasipaddress,		nasportid, \
		nasporttype,		acctstarttime,		acctupdatetime, \
		acctstoptime,		acctsessiontime, 	acctauthentic, \
		connectinfo_start,	connectinfo_stop, 	acctinputoctets, \
		acctoutputoctets,	calledstationid, 	callingstationid, \
		acctterminatecause,	servicetype,		framedprotocol, \
		framedipaddress,	framedipv6address,	framedipv6prefix, \
		framedinterfaceid,	delegatedipv6prefix) \
	VALUES \
		(acctsessionid, \
		acctuniqueid, \
		username, \
		realm, \
		nasipaddress, \
		nasportid, \
		nasporttype, \
		FROM_UNIXTIME(eventTimestamp - acctsessiontime1), \
		FROM_UNIXTIME(eventTimestamp), \
		FROM_UNIXTIME(eventTimestamp), \
		acctsessiontime2, \
		acctauthentic, \
		'', \
		connectinfo, \
		acctinputoctets, \
		acctoutputoctets, \
		calledstationid, \
		callingstationid, \
		acctterminatecause, \
		servicetype, \
		framedprotocol, \
		framedipaddress, \
		framedipv6address, \
		framedipv6prefix, \
		framedinterfaceid, \
		delegatedipv6prefix);
end //




/*
#
#  When using "sql_session_start", you should comment out
#  the previous query, and enable this one.
#
#  Just change the previous query to "-query",
#  and this one to "query".  The previous one
#  will be ignored, and this one will be
#  enabled.
#
*/
create procedure stop(AcctSessionId varchar(64),
			AcctUniqueId varchar(32),
			AcctAuthentic varchar(32),
			ConnectInfo_start varchar(50),
			ServiceType varchar(32),
			FramedProtocol varchar(32),
			framedipaddress varchar(15),
			framedipv6address varchar(45),
			framedipv6prefix varchar(45),
			framedinterfaceid varchar(44),
			delegatedipv6prefix varchar(45),
			AcctStopTime timestamp,
			AcctUpdateTime timestamp,
			AcctSessionTime int(12),
			AcctInputOctets bigint(20),
			AcctOutputOctets bigint(20),
			AcctTerminateCause varchar(32),
			ConnectInfo_stop varchar(50),
			UserName varchar(64),
			NASIPAddress varchar(15),
			NASPortId varchar(15),
			NASPortType varchar(32))
begin
	UPDATE radacct \
	SET \
		radacct.AcctSessionId = AcctSessionId, \
		radacct.AcctUniqueId = AcctUniqueId, \
		radacct.AcctAuthentic = AcctAuthentic, \
		radacct.ConnectInfo_start = ConnectInfo_start, \
		radacct.ServiceType = ServiceType, \
		radacct.FramedProtocol = FramedProtocol, \
		radacct.framedipaddress = framedipaddress, \
		radacct.framedipv6address = framedipv6address, \
		radacct.framedipv6prefix = framedipv6prefix, \
		radacct.framedinterfaceid = framedinterfaceid, \
		radacct.delegatedipv6prefix = delegatedipv6prefix, \
		radacct.AcctStopTime = FROM_UNIXTIME(AcctStopTime), \
		radacct.AcctUpdateTime = FROM_UNIXTIME(AcctUpdateTime), \
		radacct.AcctSessionTime = AcctSessionTime, \
		radacct.AcctInputOctets = AcctInputOctets, \
		radacct.AcctOutputOctets = AcctOutputOctets, \
		radacct.AcctTerminateCause = AcctTerminateCause, \
		radacct.ConnectInfo_stop = ConnectInfo_stop \
	WHERE radacct.UserName = UserName \
	AND radacct.NASIPAddress = NASIPAddress \
	AND radacct.NASPortId = NASPortId \
	AND radacct.NASPortType = NASPortType \
	AND radacct.AcctStopTime IS NULL;
end //

/*
#
#  No Acct-Status-Type == ignore the packet
#
*/
create procedure getTrue()
begin
	select true;
end //

/*
#######################################################################
# Authentication Logging Queries
#######################################################################
# postauth_query	- Insert some info after authentication
#######################################################################
*/
create procedure postAuthInfo(username varchar(64),
				pass varchar(64),
				reply varchar(32),
				authdate timestamp)
begin
	INSERT INTO radpostauth \
		(username, pass, reply, authdate) \
	VALUES ( \
		username, \
		pass, \
		reply, \
		authdate);
end //

delimiter ;
