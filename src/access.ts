import { createHash, timingSafeEqual } from "node:crypto";

export interface AccessEnv {
	ACCESS_LOCAL_DEV: string;
	MCP_BEARER_TOKEN?: string;
	WEB_ADMIN_PASSWORD?: string;
}

export function isLocalDevelopment(request: Request, env: AccessEnv): boolean {
	if (env.ACCESS_LOCAL_DEV !== "true") return false;
	const hostname = new URL(request.url).hostname;
	return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

export function isMcpRequest(request: Request): boolean {
	const { pathname } = new URL(request.url);
	return pathname === "/mcp" || pathname.startsWith("/mcp/");
}

function matchesAuthorization(request: Request, expected: string): boolean {
	const supplied = request.headers.get("Authorization");
	if (!supplied) return false;
	const [scheme, value] = supplied.split(/ +/, 2);
	const [expectedScheme, expectedValue] = expected.split(" ");
	if (scheme.toLowerCase() !== expectedScheme.toLowerCase() || !value) return false;
	const hash = (input: string) => createHash("sha256").update(input).digest();
	return timingSafeEqual(hash(value), hash(expectedValue));
}

export async function accessRejection(
	request: Request,
	env: AccessEnv,
	verify: (token: string) => Promise<unknown>,
): Promise<Response | undefined> {
	if (isLocalDevelopment(request, env)) return undefined;

	if (env.MCP_BEARER_TOKEN !== undefined || env.WEB_ADMIN_PASSWORD !== undefined) {
		const isMcp = isMcpRequest(request);
		const secret = isMcp ? env.MCP_BEARER_TOKEN : env.WEB_ADMIN_PASSWORD;
		const scheme = isMcp ? "Bearer" : "Basic";
		if (secret) {
			const credential = isMcp ? secret : btoa(`admin:${secret}`);
			if (matchesAuthorization(request, `${scheme} ${credential}`)) return undefined;
		}
		return new Response("Unauthorized", {
			status: 401,
			headers: { "WWW-Authenticate": `${scheme} realm="Email MCP"` },
		});
	}

	const token = request.headers.get("Cf-Access-Jwt-Assertion");
	if (!token)
		return new Response("Unauthorized: missing Cloudflare Access assertion", {
			status: 401,
		});

	try {
		await verify(token);
		return undefined;
	} catch {
		return new Response("Forbidden: invalid Cloudflare Access assertion", {
			status: 403,
		});
	}
}
