import {OAuth2Client} from 'google-auth-library';
import {JSONClient} from 'google-auth-library/build/src/auth/googleauth';

export interface TokenFile {
  type: string;
  client_id?: string;
  client_secret?: string;
  refresh_token?: string | null;
  access_token?: string | null;
}

export interface ClientResponse {
  client: JSONClient | OAuth2Client;
  isFresh: boolean;
  credentials: {
    client_id: string;
    client_secret: string;
  };
  tokenFile: TokenFile;
}
