import {OAuth2Client} from 'google-auth-library';
import http, {createServer} from 'node:http';
import fs from 'node:fs';
import {URL} from 'node:url';
import destroyer from 'server-destroy';
import opn from 'open';
import {JSONClient} from 'google-auth-library/build/src/auth/googleauth';
import {TokenFile} from './types/';

export async function authenticate({
  clientId,
  clientSecret,
  scopes,
  redirectUri,
  isDesktopClient,
}: {
  clientId: string;
  clientSecret: string;
  scopes: string[];
  redirectUri: string;
  isDesktopClient: boolean;
}) {
  const _redirectUri = new URL(redirectUri);

  if (_redirectUri.hostname !== 'localhost') {
    return null;
  }

  // create an oAuth client
  const client = new OAuth2Client({clientId, clientSecret});

  return new Promise<OAuth2Client | null>(resolve => {
    const server = createServer(async (req, res) => {
      try {
        if (!req.url) {
          resolve(null);
          return;
        }

        const url = new URL(req.url, 'http://localhost:3000');

        if (url.pathname !== _redirectUri.pathname) {
          res.end('Invalid callback URL');
          return;
        }

        const searchParams = url.searchParams;

        if (searchParams.has('error')) {
          res.end('Authorization rejected.');
          resolve(null);
          return;
        }

        if (!searchParams.has('code')) {
          res.end('No auth code passed');
          resolve(null);
          return;
        }

        const code = searchParams.get('code');

        if (!code) {
          resolve(null);
          return;
        }

        const {tokens} = await client.getToken({
          code,
          redirect_uri: _redirectUri.toString(),
        });

        client.credentials = tokens;
        resolve(client);
        res.end('Authentication successful! Please return to the console.');
      } catch (e) {
        resolve(null);
      } finally {
        server.close();
      }
    });

    let _port = 3000;

    if (isDesktopClient) {
      _port = 0;
    } else {
      _port = Number(_redirectUri.port);
    }

    server.listen(_port, () => {
      const address = server.address();

      if (!address) {
        return;
      }

      if (typeof address === 'string') {
        return;
      }

      if (address.port !== undefined) {
        _redirectUri.port = address.port.toString();
      }

      // open the browser to the authorize url to start the workflow
      const authorizeUrl = client.generateAuthUrl({
        redirect_uri: _redirectUri.toString(),
        access_type: 'offline',
        scope: scopes.join(' '),
      });

      console.log('Auth URL', authorizeUrl);

      opn(authorizeUrl, {wait: false}).then(cp => cp.unref());
    });
    destroyer(server);
  });
}

export async function refresh_token(
  client: JSONClient | OAuth2Client,
  payload: any,
  TOKEN_PATH: string,
) {
  try {
    client.on('tokens', tokens => {
      console.log('Token refresh available');

      const tokenFile = JSON.stringify({
        ...payload,
        access_token: tokens.access_token,
      });

      fs.writeFile(TOKEN_PATH, tokenFile, err => {});
      client.setCredentials({
        access_token: tokens.access_token,
      });
    });
  } catch (e) {}
}

export async function saveCredentials(
  tokenFile: TokenFile,
  TOKEN_PATH: string,
) {
  return new Promise<boolean>(resolve => {
    try {
      const _tokenFile = JSON.stringify(tokenFile);
      fs.writeFile(TOKEN_PATH, _tokenFile, err => resolve(err ? false : true));
    } catch (e) {
      resolve(false);
    }
  });
}
