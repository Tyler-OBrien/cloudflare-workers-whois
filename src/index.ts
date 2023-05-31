//@ts-ignore ts dumb
import whoiser from './whoiser';
export interface Env {
}

const HTML = `<!DOCTYPE html>
<html>
<head>
    <title>Whois Search</title>
    <script>
        function search(event) {
            event.preventDefault();  // prevent the form from doing a page reload on submit

            var searchQuery = document.getElementById('searchQuery').value;

            fetch('/api/search', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({query: searchQuery})  // send the search query in the body of the POST request
            })
            .then(response => response.json())  // parse the response as JSON
            .then(data => {
                document.getElementById('response').textContent = JSON.stringify(data, null, 2);  // display the response JSON in the pre block
            })
            .catch(error => console.error('Error:', error));
        }
    </script>
</head>
<body>
    <form onsubmit="search(event)">
        <input type="text" id="searchQuery" placeholder="Enter domain name, IP, ASN, or anything whois searchable" />
        <button type="submit">Search</button>
    </form>
    <pre id="response"></pre>
</body>
</html>
`

export default {
	async fetch(
		request: Request,
		env: Env,
		ctx: ExecutionContext
	): Promise<Response> {
		var url = new URL(request.url);
		if (url.pathname === '/') {
			return new Response(HTML, {
				headers: {
					'content-type': 'text/html;charset=UTF-8',
				},
			});
		}
		if (url.pathname !== '/api/search') {
			return new Response('Not found', { status: 404 });
		}
		if (request.method !== 'POST') {
			return new Response('Method not allowed', { status: 405 });
		}
		var contentType = request.headers.get('content-type');
		if (contentType !== 'application/json') {
			return new Response('Bad request', { status: 400 });
		}
		var body = await request.json();
		if (!body.query) {
			return new Response('No query specified', { status: 400 });
		}
		var data = await whoiser(body.query);
		return new Response(JSON.stringify(data), {
			headers: {
				'content-type': 'application/json;charset=UTF-8',
			},
		});
	},
};
