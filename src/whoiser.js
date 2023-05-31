import { connect } from 'cloudflare:sockets';
const punycode = require('punycode/')
const { parseSimpleWhois, parseDomainWhois } = require('./parsers.js')
const { splitStringBy, requestGetBody, isTld, isDomain } = require('./utils.js')

// Cache WHOIS servers
// Basic list of servers, more will be auto-discovered
let cacheTldWhoisServer = {
	com: 'whois.verisign-grs.com',
	net: 'whois.verisign-grs.com',
	org: 'whois.pir.org',

	// ccTLDs
	ai: 'whois.nic.ai',
	au: 'whois.auda.org.au',
	co: 'whois.nic.co',
	ca: 'whois.cira.ca',
	do: 'whois.nic.do',
	gl: 'whois.nic.gl',
	in: 'whois.registry.in',
	io: 'whois.nic.io',
	it: 'whois.nic.it',
	me: 'whois.nic.me',
	ro: 'whois.rotld.ro',
	rs: 'whois.rnids.rs',
	so: 'whois.nic.so',
	us: 'whois.nic.us',
	ws: 'whois.website.ws',

	agency: 'whois.nic.agency',
	app: 'whois.nic.google',
	biz: 'whois.nic.biz',
	country: 'whois.uniregistry.net', // hardcoded because `whois.iana.org` sometimes returns 'whois.uniregistry.net' or 'whois.nic.country'
	dev: 'whois.nic.google',
	house: 'whois.nic.house',
	info: 'whois.nic.info',
	link: 'whois.uniregistry.net',
	live: 'whois.nic.live',
	nyc: 'whois.nic.nyc',
	one: 'whois.nic.one',
	online: 'whois.nic.online',
	shop: 'whois.nic.shop',
	site: 'whois.nic.site',
	xyz: 'whois.nic.xyz',
}

// misspelled whois servers..
const misspelledWhoisServer = {
	//'whois.google.com': 'whois.nic.google',	// Why was this added??
	'www.gandi.net/whois': 'whois.gandi.net',
	'who.godaddy.com/': 'whois.godaddy.com',
	'whois.godaddy.com/': 'whois.godaddy.com',
	'www.nic.ru/whois/en/': 'whois.nic.ru',
	'www.whois.corporatedomains.com': 'whois.corporatedomains.com',
	'www.safenames.net/DomainNames/WhoisSearch.aspx': 'whois.safenames.net',
	'WWW.GNAME.COM/WHOIS': 'whois.gname.com',
}

// Translate WHOIS host to IP, so connection is faster
const whoisHostToIp = {
	'whois.google.com': '216.239.34.22',
}

const whoisQuery = ({ host = null, port = 43, timeout = 15000, query = '', querySuffix = '\r\n' } = {}) => {
	return new Promise(async (resolve, reject) => {
		try {
		console.log(`Trying to connect to ${host}:${port}, query: ${query}, querySuffix: ${querySuffix}`)
		const socket = connect(`${host}:${port}`);

		const writer = socket.writable.getWriter()
		const encoder = new TextEncoder();
		const encoded = encoder.encode(query + querySuffix);
		await writer.write(encoded);
		var newResponse = new Response(socket.readable);
		var newBody = await newResponse.text();
		socket.close();
		resolve(newBody);
		}
		catch (error) {
			console.log(error)
			reject(error);
		}
	})
}

const allTlds = async () => {
	const tlds = await requestGetBody('https://data.iana.org/TLD/tlds-alpha-by-domain.txt')

	return tlds.split('\n').filter((tld) => Boolean(tld) && !tld.startsWith('#'))
}

const whoisTldAlternate = async (query) => {
	const [whoisCname, whoisSrv] = await Promise.allSettled([
		// Check sources for whois server
		lookup(`${query}.whois-servers.net`, 'CNAME'), // Queries public database for whois server
		lookup(`_nicname._tcp.${query}`, 'SRV'), // Queries for whois server published by registry
	])
	if (whoisSrv) {
		var lastSpaceIndex = whoisSrv.lastIndexOf(' ');
    	var lastPart = string.substring(lastSpaceIndex + 1);
		if (lastPart.length != 0)
			return lastPart;
	}

	return whoisCname;
}
const lookup = async (query, type) => {
	let doHResponse = await fetch(`https://cloudflare-dns.com/dns-query?type=${type}&name=${query}`, {
		headers: {
			"Accept": "application/dns-json"
		}
	});

	if (doHResponse.ok === false) 
		return null;
	// This type only includes the data we need.
	let doHResponseJSON = await doHResponse.json();
	return doHResponseJSON.Answer[0].data;
}

const whoisTld = async (query, { timeout = 15000, raw = false, domainTld = '' } = {}) => {
	const result = await whoisQuery({ host: 'whois.iana.org', query, timeout })
	const data = parseSimpleWhois(result)

	if (raw) {
		data.__raw = result
	}

	// if no whois server found, search in more sources
	if (!data.whois) {

		//todo
		// instead of using `domainTld`, split `query` in domain parts and request info for all tld combinations
		// example: query="example.com.tld" make 3 requests for "example.com.tld" / "com.tld" / "tld"

		const whois = await whoisTldAlternate(domainTld || query)

		if (whois) {
			data.whois = whois
			data.domain = data.domain || whois
		}
	}

	if (!data.domain && !data.whois) {
		throw new Error(`TLD "${query}" not found`)
	}

	return data
}

const whoisDomain = async (domain, { host = null, timeout = 15000, follow = 2, raw = false, ignorePrivacy = true } = {}) => {
	domain = punycode.toASCII(domain)
	const [domainName, domainTld] = splitStringBy(domain.toLowerCase(), domain.lastIndexOf('.'))
	let results = {}

	// find WHOIS server in cache
	if (!host && cacheTldWhoisServer[domainTld]) {
		host = cacheTldWhoisServer[domainTld]
	}

	// find WHOIS server for TLD
	if (!host) {
		const tld = await whoisTld(domain, { timeout, domainName, domainTld })

		if (!tld.whois) {
			throw new Error(`TLD for "${domain}" not supported`)
		}

		host = tld.whois
		cacheTldWhoisServer[domainTld] = tld.whois
	}

	// query WHOIS servers for data
	while (host && follow) {
		let query = domain
		let result
		let resultRaw

		// hardcoded WHOIS queries..
		if (host === 'whois.denic.de') {
			query = `-T dn ${punycode.toUnicode(domain)}`
		} else if (host === 'whois.jprs.jp') {
			query = `${query}/e`
		}

		try {
			resultRaw = await whoisQuery({ host, query, timeout })
			result = parseDomainWhois(domain, resultRaw, ignorePrivacy)
		} catch (err) {
			result = { error: err.message }
		}

		if (raw) {
			result.__raw = resultRaw
		}

		results[host] = result
		follow--

		// check for next WHOIS server
		let nextWhoisServer =
			result['Registrar WHOIS Server'] ||
			result['Registry WHOIS Server'] ||
			result['ReferralServer'] ||
			result['Registrar Whois'] ||
			result['Whois Server'] ||
			result['WHOIS Server'] ||
			false

		// fill in WHOIS servers when missing
		if (!nextWhoisServer && result['Registrar URL'] && result['Registrar URL'].includes('domains.google')) {
			nextWhoisServer = 'whois.google.com'
		}

		if (nextWhoisServer) {
			// if found, remove protocol and path
			if (nextWhoisServer.includes('://')) {
				let parsedUrl = new URL(nextWhoisServer)
				//todo use parsedUrl.port, if defined
				nextWhoisServer = parsedUrl.hostname
			}

			// check if found server is in misspelled list
			nextWhoisServer = misspelledWhoisServer[nextWhoisServer] || nextWhoisServer

			// check if found server was queried already
			nextWhoisServer = !results[nextWhoisServer] ? nextWhoisServer : false
		}

		host = nextWhoisServer
	}

	return results
}

const isIP = (ip) => {
	var ipv4Pattern = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    var ipv6Pattern = /^([0-9a-f]{1,4}:){7,7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|:((:[0-9a-f]{1,4}){1,7}|:)|fe80:(:[0-9a-f]{0,4}){0,4}%[0-9a-z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-f]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$/;
    return ipv4Pattern.test(ip) || ipv6Pattern.test(ip);
}

const whoisIpOrAsn = async (query, { host = null, timeout = 15000, follow = 2, raw = false } = {}) => {
	const type = isIP(query) ? 'ip' : 'asn'
	query = String(query)

	// find WHOIS server for IP
	if (!host) {
		let whoisResult = await whoisQuery({ host: 'whois.iana.org', query, timeout })
		whoisResult = parseSimpleWhois(whoisResult)

		if (whoisResult.whois) {
			host = whoisResult.whois
		}
	}

	if (!host) {
		throw new Error(`No WHOIS server for "${query}"`)
	}

	let data

	while (host && follow) {
		let modifiedQuery = query

		// hardcoded custom queries..
		if (host === 'whois.arin.net' && type === 'ip') {
			modifiedQuery = `+ n ${query}`
		} else if (host === 'whois.arin.net' && type === 'asn') {
			modifiedQuery = `+ a ${query}`
		}

		const rawResult = await whoisQuery({ host, query: modifiedQuery, timeout })
		data = parseSimpleWhois(rawResult)

		if (raw) {
			data.__raw = rawResult
		}

		follow--
		host = data?.ReferralServer?.split('//')?.[1]
	}

	return data
}

const firstResult = (whoisResults) => {
	const whoisServers = Object.keys(whoisResults)

	return whoisServers.length ? whoisResults[whoisServers[0]] : null
}

module.exports = (query, options) => {
	if (isIP(query) || /^(as)?\d+$/i.test(query)) {
		return whoisIpOrAsn(query, options)
	} else if (isTld(query)) {
		return whoisTld(query, options)
	} else if (isDomain(query)) {
		return whoisDomain(query, options)
	}

	throw new Error('Unrecognized query. Try a domain (google.com), IP (1.1.1.1) or TLD (.blog)')
}

module.exports.query = whoisQuery
module.exports.tld = whoisTld
module.exports.domain = whoisDomain
module.exports.asn = whoisIpOrAsn
module.exports.ip = whoisIpOrAsn
module.exports.allTlds = allTlds
module.exports.firstResult = firstResult
