import { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { OAuthClientInformationFull, OAuthTokens, OAuthTokenRevocationRequest } from "@modelcontextprotocol/sdk/shared/auth.js";
import { Response } from "express";
import { ConfidentialClientApplication } from "@azure/msal-node";
import { ClientWithVerifier } from "./ClientWithVerifier.js";
import fs from 'fs/promises';
import path from 'path';
import dotenv from 'dotenv';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import { tokenStore } from './TokenStore.js';
import { SessionData } from "./SessionData.js";

export class EntraIdServerAuthProvider implements OAuthServerProvider {
    private _clientsMap: Map<string, OAuthClientInformationFull> = new Map();
    private _clientsStoreImpl: OAuthRegisteredClientsStore;
    private _clientsFilePath: string;
    private _sessionStore: Map<string, SessionData> = new Map();
    private _confidentialClient: ConfidentialClientApplication;
    private _tempAuthCodes: Map<string, { sessionToken: string, expires: number }> = new Map();

    /**
     * Creates a new instance of EntraIdServerAuthProvider
     */
    constructor() {
        dotenv.config();

        const requiredEnvVars = ['FR_TENANT_ID', 'FR_API_CLIENT_SECRET', 'FR_API_CLIENT_ID'];

        const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
        if (missingEnvVars.length > 0) {
            throw new Error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
        }

        this._confidentialClient = new ConfidentialClientApplication({
            auth: {
                clientId: process.env.FR_API_CLIENT_ID!,
                clientSecret: process.env.FR_API_CLIENT_SECRET!,
                authority: `https://login.microsoftonline.com/${process.env.FR_TENANT_ID!}`
            }
        });

        this._clientsFilePath = path.resolve(process.cwd(), 'registered_clients.json');

        this._clientsStoreImpl = {
            getClient: (clientId: string) => {
                console.log("Getting client ", clientId);
                return this._clientsMap.get(clientId);
            },

            registerClient: (client: OAuthClientInformationFull) => {
                this._clientsMap.set(client.client_id, client);
                console.log("Registered client ", client.client_id);

                this._saveClientsToFile().catch(err => {
                    console.error("Failed to save client registration:", err);
                });
                return client;
            }
        };

        this._loadClientsFromFile().catch(err => {
            console.error("Failed to load registered clients:", err);
        });

        setInterval(() => {
            tokenStore.cleanExpiredTokens();
        }, 60000);
    }

    private generatePkce(): { verifier: string, challenge: string } {
        // Generate a random code verifier (43-128 chars)
        const verifier = uuidv4() + uuidv4() + uuidv4();

        // Create code challenge by hashing verifier with SHA256 and base64url encoding
        const challenge = crypto.createHash('sha256')
            .update(verifier)
            .digest('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        return { verifier, challenge };
    }

    /**
     * Stores session data in memory using the state parameter as key
     * @param state - The state parameter used as the lookup key
     * @param data - The session data to store
     */
    private async _storeSessionData(state: string, data: SessionData): Promise<void> {
        if (!state) {
            throw new Error("Cannot store session data: state parameter is missing");
        }

        this._sessionStore.set(state, data);
        console.log(`Session data stored for state: ${state}`);
    }

    /**
     * Retrieves session data for a given state
     * @param state - The state parameter used as the lookup key
     * @returns The session data or undefined if not found
     */
    private _getSessionData(state: string): SessionData | undefined {
        return this._sessionStore.get(state);
    }

    /**
     * Removes session data after it's been used
     * @param state - The state parameter used as the lookup key
     */
    private _clearSessionData(state: string): void {
        this._sessionStore.delete(state);
        console.log(`Session data cleared for state: ${state}`);
    }

    /**
     * Load registered clients from file
     */
    private async _loadClientsFromFile(): Promise<void> {
        try {
            await fs.access(this._clientsFilePath)
                .catch(() => {
                    console.log("No saved clients file found. Starting with empty clients list.");
                    return Promise.reject(new Error("File not found"));
                });

            const fileContent = await fs.readFile(this._clientsFilePath, { encoding: 'utf8' });
            const clientsData = JSON.parse(fileContent);

            this._clientsMap.clear();
            for (const [clientId, clientData] of Object.entries(clientsData)) {
                this._clientsMap.set(clientId, clientData as OAuthClientInformationFull);
            }

            console.log(`Loaded ${this._clientsMap.size} registered clients from file.`);
        } catch (err) {
            if ((err as Error).message !== "File not found") {
                console.error("Error loading clients from file:", err);
            }
        }
    }

    /**
     * Save registered clients to file
     */
    private async _saveClientsToFile(): Promise<void> {
        try {
            const clientsObject: Record<string, OAuthClientInformationFull> = {};
            for (const [clientId, clientData] of this._clientsMap.entries()) {
                clientsObject[clientId] = clientData;
            }

            await fs.writeFile(
                this._clientsFilePath,
                JSON.stringify(clientsObject, null, 2),
                { encoding: 'utf8' }
            );

            console.log(`Saved ${this._clientsMap.size} registered clients to file.`);
        } catch (err) {
            console.error("Error saving clients to file:", err);
            throw err;
        }
    }

    /**
     * Gets the clients store implementation
     */
    get clientsStore(): OAuthRegisteredClientsStore {
        return this._clientsStoreImpl;
    }

    /**
     * Authorizes a client and redirects to Entra ID login
     * @param client - Client information
     * @param params - Authorization parameters
     * @param res - Express response object
     */
    async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
        console.log("Authorizing client ", client.client_id);

        try {
            const redirectUri = client.redirect_uris[0] as string;

            // Generate our own PKCE values instead of using client's
            const pkce = this.generatePkce();
            const codeChallengeMethod = 'S256';

            // Generate a secure random state parameter
            const state = crypto.randomBytes(32).toString('hex');

            // Store both the client's original state and our generated state
            const sessionData: SessionData = {
                clientId: client.client_id,
                state: state,
                codeVerifier: pkce.verifier,  // Store our verifier for later
                redirectUri: redirectUri,
                originalState: params.state as string,  // Store client's original state
                clientCodeChallenge: params.codeChallenge as string,
                clientCodeChallengeMethod: 'S256'
            };

            await this._storeSessionData(state, sessionData);

            const authCodeUrlParameters = {
                scopes: ['User.Read'],
                redirectUri: 'http://localhost:3001/auth/callback',
                codeChallenge: pkce.challenge,  // Use our challenge
                codeChallengeMethod: codeChallengeMethod,
                state: state,
                prompt: 'select_account'
            };

            const authUrl = await this._confidentialClient.getAuthCodeUrl(authCodeUrlParameters);

            res.redirect(authUrl);

        } catch (error) {
            console.error("Authorization setup error:", error);
            res.status(500).send("Failed to initialize authentication: " + error);
        }
    }

    /**
     * Returns the code challenge for a given authorization code
     * @param client - Client information
     * @param authorizationCode - The authorization code
     * @returns Promise with the code challenge
     */
    async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
        try {
            // Look up the temporary authorization code
            const tempCodeData = this._tempAuthCodes.get(authorizationCode);
            if (!tempCodeData || tempCodeData.expires < Date.now()) {
                this._tempAuthCodes.delete(authorizationCode); // Clean up expired code
                throw new Error("Invalid or expired authorization code");
            }

            // Get the session token to find the associated challenge
            const sessionToken = tempCodeData.sessionToken;
            const storedToken = tokenStore.getToken(sessionToken);

            if (!storedToken) {
                throw new Error("Invalid session token");
            }

            // Return the code challenge that was stored during authorization
            return storedToken.clientCodeChallenge || '';
        } catch (error) {
            console.error("Error retrieving code challenge:", error);
            throw new Error(`Failed to get code challenge: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Exchanges a refresh token for new OAuth tokens
     * @param client - Client information
     * @param refreshToken - The refresh token
     * @param scopes - Optional scopes to request
     * @returns Promise with OAuth tokens
     */
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string, scopes?: string[]): Promise<OAuthTokens> {
        // TODO: Implement refresh token functionality
        throw new Error("Refresh token exchange not implemented");
    }

    /**
     * Verifies an access token and returns authentication information.
     * This method is invoked in the context of bearerAuth infra inside
     * the auth middleware. It get an AuthInfo object and then checks if
     * all required sceopes are included or the token has expired. It assumes
     * that the bulk of validation (beyond that) happens here.
     * @param token - The access token to verify
     * @returns Promise with authentication information
     */
    async verifyAccessToken(token: string): Promise<AuthInfo> {
        const storedToken = tokenStore.getToken(token);

        if (!storedToken) {
            throw new Error("Invalid or expired token");
        }

        // Check if token has expired
        if (storedToken.expiresAt < Date.now()) {
            tokenStore.removeToken(token);
            throw new Error("Token has expired");
        }

        return {
            token: token,
            clientId: storedToken.clientId,
            scopes: storedToken.scopes,
            expiresAt: storedToken.expiresAt
        };
    }

    /**
     * Revokes an OAuth token
     * @param client - Client information
     * @param request - Token revocation request
     * @returns Promise indicating completion
     */
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
        throw new Error("Token revocation not implemented");
    }

    async exchangeAuthorizationCode(client: ClientWithVerifier, authorizationCode: string): Promise<OAuthTokens> {
        try {
            console.log(`Exchanging authorization code for client ${client.client_id}`);

            // Look up the temporary authorization code
            const tempCodeData = this._tempAuthCodes.get(authorizationCode);
            if (!tempCodeData || tempCodeData.expires < Date.now()) {
                this._tempAuthCodes.delete(authorizationCode); // Clean up expired code
                throw new Error("Invalid or expired authorization code");
            }

            // This is a one-time use code, delete it immediately
            this._tempAuthCodes.delete(authorizationCode);

            // Get the actual session token
            const sessionToken = tempCodeData.sessionToken;
            const storedToken = tokenStore.getToken(sessionToken);

            if (!storedToken) {
                throw new Error("Invalid session token");
            }

            // Return the session token as the access token
            return {
                access_token: sessionToken,
                token_type: "Bearer",
                expires_in: Math.floor((storedToken.expiresAt - Date.now()) / 1000),
                refresh_token: crypto.randomBytes(32).toString('hex'), // Generate a proxy refresh token
                scope: storedToken.scopes.join(' ')
            };
        } catch (error) {
            console.error("Error exchanging authorization code for tokens:", error);
            throw new Error(`Failed to exchange authorization code: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Handles the OAuth callback from Entra ID
     * @param code - Authorization code from callback
     * @param state - State parameter from callback
     * @returns Information needed to complete the redirect
     */
    public async handleCallback(code: string, state: string): Promise<{
        redirectUrl: string;
        success: boolean;
        error?: string;
    }> {
        try {
            const sessionData = this._getSessionData(state);
            if (!sessionData) {
                return { redirectUrl: '', success: false, error: "Invalid state parameter" };
            }

            const tokenResponse = await this._confidentialClient.acquireTokenByCode({
                code: code,
                codeVerifier: sessionData.codeVerifier,
                redirectUri: 'http://localhost:3001/auth/callback',
                scopes: ['User.Read']
            });

            // Store the token and get a session token (this will be our actual access token that we'll pass to the client)
            const sessionToken = tokenStore.storeToken(
                tokenResponse.accessToken,
                '',
                tokenResponse.expiresOn ?
                    Math.floor((tokenResponse.expiresOn.getTime() - Date.now()) / 1000) :
                    3600,
                sessionData.clientId,
                tokenResponse.scopes || ['User.Read'],
                sessionData.clientCodeChallenge,
                sessionData.clientCodeChallengeMethod
            );

            // Create a temporary, single-use authorization code
            const tempAuthCode = crypto.randomBytes(32).toString('hex');

            // Store mapping between temp auth code and session token with 5-minute expiration
            this._tempAuthCodes.set(tempAuthCode, {
                sessionToken: sessionToken,
                expires: Date.now() + 5 * 60 * 1000 // 5 minutes
            });

            // Schedule cleanup of this temporary code
            setTimeout(() => {
                this._tempAuthCodes.delete(tempAuthCode);
            }, 5 * 60 * 1000);

            // Create client redirect with temporary authorization code
            const clientRedirectUrl = new URL(sessionData.redirectUri);
            clientRedirectUrl.searchParams.append("code", tempAuthCode);
            clientRedirectUrl.searchParams.append("state", sessionData.originalState || "");

            // Clean up the authentication session data
            this._clearSessionData(state);

            return {
                redirectUrl: clientRedirectUrl.toString(),
                success: true
            };
        } catch (error) {
            console.error("Callback handling error:", error);
            return {
                redirectUrl: '',
                success: false,
                error: `Authentication callback failed: ${error instanceof Error ? error.message : String(error)}`
            };
        }
    }
}