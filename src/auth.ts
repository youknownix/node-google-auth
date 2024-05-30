import {OAuth2Client} from 'google-auth-library';
import {JSONClient} from 'google-auth-library/build/src/auth/googleauth';
import {authenticate, refresh_token, saveCredentials} from './methods';
import {google} from 'googleapis';
import fs from 'node:fs';
import path from 'node:path';
import {ClientResponse} from './types/';

const DEFAULT_SCOPES = [
  'https://www.googleapis.com/auth/spreadsheets',
  'https://www.googleapis.com/auth/drive',
];

const TOKEN_PATH = path.join(process.cwd(), '.g-token');

async function getClient(): Promise<ClientResponse | null> {
  const {
    google_client_id,
    google_client_secret,
    google_redirect_uris,
    google_client_scopes,
  } = process.env;

  if (!google_client_id) {
    console.log('google_client_id not passed');
    return null;
  }

  let $scopes: string[];

  if (!google_client_scopes) {
    $scopes = DEFAULT_SCOPES;
  } else {
    $scopes = google_client_scopes.split(';');
  }

  if (!google_client_secret) {
    console.log('google_client_secret not passed');
    return null;
  }

  if (!google_redirect_uris) {
    console.log('google_redirect_uris not passed');
    return null;
  }

  const credentials = {
    client_id: google_client_id,
    client_secret: google_client_secret,
  };

  try {
    if (fs.existsSync(TOKEN_PATH)) {
      const tokenFile = fs.readFileSync(TOKEN_PATH);
      const content = JSON.parse(Buffer.from(tokenFile).toString('ascii'));
      const localClient = google.auth.fromJSON(content);

      return {
        client: localClient,
        isFresh: false,
        credentials,
        tokenFile: content,
      };
    }
  } catch (e) {}

  let redirectUri: string;

  try {
    redirectUri = JSON.parse(google_redirect_uris)[0];
  } catch (e) {
    console.log('Invalid google_redirect_uris passed');
    return null;
  }

  try {
    const client = await authenticate({
      clientId: google_client_id,
      clientSecret: google_client_secret,
      scopes: $scopes,
      redirectUri,
      isDesktopClient: true,
    });

    if (client && client.credentials) {
      return {
        client,
        isFresh: true,
        credentials,
        tokenFile: {
          type: 'authorized_user',
          client_id: client._clientId,
          client_secret: client._clientSecret,
          access_token: client.credentials.access_token,
          refresh_token: client.credentials.refresh_token,
        },
      };
    }

    throw Error();
  } catch (e) {
    console.log('Failed to get client', e);
    return null;
  }
}

export function authorizeGoogle() {
  return new Promise<JSONClient | OAuth2Client | null>(async resolve => {
    const client = await getClient();

    if (!client) {
      resolve(null);
      return;
    }

    refresh_token(client.client, client.tokenFile, TOKEN_PATH);

    if (client.isFresh) {
      await saveCredentials(client.tokenFile, TOKEN_PATH);
      resolve(client.client);
      return;
    }

    try {
      const client_id = client.credentials.client_id;
      const client_secret = client.credentials.client_secret;
      const refresh_token = client.client?.credentials.refresh_token ?? ':';

      // resfresh token
      const res = await fetch(
        'https://oauth2.googleapis.com/token?' +
          new URLSearchParams({
            client_id,
            client_secret,
            refresh_token,
            grant_type: 'refresh_token',
          }),
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
      );

      const body = await res.json();

      if (
        body.access_token &&
        body.access_token !== null &&
        typeof body.access_token !== 'undefined'
      ) {
        saveCredentials(
          {
            type: 'authorized_user',
            client_id,
            client_secret,
            refresh_token,
            access_token: body.access_token,
          },
          TOKEN_PATH,
        );

        client.client.setCredentials({access_token: body.access_token});

        resolve(client.client);
      } else {
        console.log('RefreshTokenResponse', body);
      }
    } catch (e) {
      console.log('Failed to send client');
      resolve(null);
    }
  });
}
