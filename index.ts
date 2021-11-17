import { NextFunction, Request, Response } from "express";
import url from "url";
import https from "https";

export enum EAssuranceLevel {
    NO_ASSURANCE = 0,
    LOW = 10,
    MEDIUM = 20,
    HIGH = 30,
    INTERNAL = 40,
    TOP = 40
}

export enum ECasVersion {V1 = '1.0', V2 = '2.0', V3 = '3.0'}

enum EAuthType { BOUNCE = 0, BOUNCE_REDIRECT = 1, BLOCK = 2}

export enum EValidateUri {
    SERVICEVALIDATE = '/serviceValidate',
    STRICTVALIDATE = '/strictValidate',
    INTERINSTITUTIONALVALIDATE = '/interinstitutionalValidate',
    SPONSORVALIDATE = '/sponsorValidate',
    LAXVALIDATE = '/laxValidate',
}

export enum ECasUrls {
    ACCEPTANCE = 'https://ecas.acceptance.ec.europa.eu/cas',
    PRODUCTION = 'https://ecas.ec.europa.eu/cas'
}

interface IConfig {
    casUrl?: string;
    validateUri?: EValidateUri;
    serviceUrl: string;
    logoutRedirectUrl?: string;
    casVersion?: string;
    sessionName?: string;
    sessionInfo?: string;
    destroySession?: boolean;
    renew?: boolean;
    isDevMode?: boolean;
    devModeUser?: string;
    devModeInfo?: {};
    assuranceLevel?: EAssuranceLevel;
}

export class EuLogin {
    private static _validateUri: string | undefined;
    private static _casHost: string;
    private static _casPort: number;
    private static _casPath: string;
    private static _httpClient: any;
    private static _assuranceLevel: number;
    private static _devModeInfo: object;
    private static _devModeUser: string;
    private static _isDevMode: boolean;
    private static _renew: boolean;
    private static _destroySession: boolean;
    private static _sessionInfo: string;
    private static _casVersion: string;
    private static _sessionName: string;
    private static _serviceUrl: string;
    private static _casUrl: string;
    private static _logoutRedirectUrl: string;

    constructor(private config: IConfig
    ) {
        if (config.serviceUrl === undefined || config.serviceUrl.length === 0) {
            throw new Error('CAS Authentication requires a serviceUrl parameter.');
        }
        this.setServiceUrl(config.serviceUrl);
        this.setCasUrl((config.casUrl !== undefined && config.casUrl.length > 0) ? config.casUrl : ECasUrls.ACCEPTANCE);
        this.setCasVersion((config.casVersion !== undefined && config.casVersion.length > 0) ? config.casVersion : ECasVersion.V3);
        this.setSessionName((config.sessionName !== undefined && config.sessionName.length > 0) ? config.sessionName : 'ecas_session');
        this.setSessionInfo((config.sessionInfo !== undefined && config.sessionInfo.length > 0) ? config.sessionInfo : 'ecas_session_info');
        this.setDestroySession(config.destroySession !== undefined ? config.destroySession : false);
        this.setRenew(config.renew !== undefined ? config.renew : false);
        this.setIsDevMode(config.isDevMode !== undefined ? config.isDevMode : false);
        this.setDevModeUser(config.devModeUser !== undefined ? config.devModeUser : '');
        this.setDevModeInfo(config.devModeInfo !== undefined ? config.devModeInfo : {});
        this.setAssuranceLevel(config.assuranceLevel !== undefined ? config.assuranceLevel : EAssuranceLevel.TOP);

        this.setValidateUri((config.validateUri !== undefined && config.validateUri.length > 0) ? config.validateUri : EValidateUri.SERVICEVALIDATE);

        this.setLogoutRedirectUrl((config.logoutRedirectUrl !== undefined && config.logoutRedirectUrl.length > 0) ? config.logoutRedirectUrl : '');

        const parsedCasUrl: url.UrlWithStringQuery = url.parse(EuLogin._casUrl);
        this.setHttpClient(https);
        this.setCasHost(parsedCasUrl.hostname ? parsedCasUrl.hostname : '');
        this.setCasPort(parsedCasUrl.protocol ? +parsedCasUrl.protocol : 443);
        this.setCasPath(parsedCasUrl.pathname ? parsedCasUrl.pathname : '');

    }

    private static handle(req: Request, res: Response, next: NextFunction, authType: EAuthType) {
        // If the session has been validated with CAS, no action is required.
        const reqSession: any = req.session;
        if (reqSession[EuLogin._sessionName]) {
            // If this is a bounce redirect, redirect the authenticated user.
            if (authType === EAuthType.BOUNCE_REDIRECT) {
                res.redirect(reqSession.cas_return_to);
            }
            // Otherwise, allow them through to their request.
            else {
                next();
            }
        }
        // If dev mode is active, set the CAS user to the specified dev user.
        else if (this._isDevMode) {
            reqSession[EuLogin._sessionName] = this._devModeUser;
            reqSession[EuLogin._sessionInfo] = this._devModeInfo;
            next();
        }
        // If the authentication type is BLOCK, simply send a 401 response.
        else if (authType === EAuthType.BLOCK) {
            res.sendStatus(401);
        }
        // If there is a CAS ticket in the query string, validate it with the CAS server.
        else if (req.query && req.query.ticket) {
            EuLogin.handleTicket(req, res);
        }
        // Otherwise, redirect the user to the CAS login.
        else {
            EuLogin.login(req, res);
        }
    }

    private static login(req: Request, res: Response) {
        const reqSession: any = req.session;
        // Save the return URL in the session. If an explicit return URL is set as a
        // query parameter, use that. Otherwise, just use the URL from the request.
        reqSession.cas_return_to = req.query.returnTo || url.parse(req.url).path;

        // Set up the query parameters.
        const queryParams = {
            service: this._serviceUrl + url.parse(req.url).pathname,
            renew: this._renew
        };
        // Redirect to the CAS login.
        res.redirect(this._casUrl + url.format({
            pathname: '/login',
            query: queryParams
        }));
    }

    private static handleTicket(req: Request, res: Response) {
        const requestOptions: any = {
            host: this._casHost,
            port: this._casPort
        }
        const reqQuery: any = req.query;
        if (['3.0'].indexOf(this._casVersion) >= 0) {
            requestOptions.method = 'GET';
            requestOptions.path = url.format({
                pathname: this._casPath + this._validateUri,
                query: {
                    service: this._serviceUrl + url.parse(req.url).pathname,
                    ticket: reqQuery.ticket,
                    userDetails: true,
                    format: 'JSON',
                    assuranceLevel: this._assuranceLevel
                }
            });
        }
        const request = this._httpClient.request(requestOptions, (response: any) => {
            response.setEncoding('utf8');
            let body = '';
            response.on('data', (chunk: any) => {
                return body += chunk;
            });
            response.on('end', () => {
                const bodyResponse: any = JSON.parse(body);
                const failure = bodyResponse.serviceResponse.authenticationFailure;
                if (failure) {
                    return res.status(401).json({ "message": 'CAS authentication failed (' + failure.code + ').' });
                }
                const success: any = bodyResponse.serviceResponse.authenticationSuccess;
                if (success) {
                    // @ts-ignore
                    req.session[EuLogin._sessionName] = {
                        userId: success.user,
                        domain: success.domain,
                        departmentNumber: success.departmentNumber ? success.departmentNumber : '',
                        orgId: success.orgId ? success.orgId : '',
                        email: success.email,
                        firstName: success.firstName,
                        lastName: success.lastName,
                        loginDate: success.loginDate,
                    };
                    // @ts-ignore
                    res.redirect(req.session.cas_return_to);
                }
                response.on('error', (error: any) => {
                    return res.status(401).json({ "message": "Response error from CAS" });
                });
            });
        });

        request.on('error', (error: any) => {
            res.status(401).json({ "message": "Request error with CAS" });
        });

        request.end();
    }

    logout(req: Request, res: Response) {
        // Destroy the entire session if the option is set.
        if (EuLogin._destroySession) {
            req.session.destroy((err) => {
                if (err) {
                    return res.status(401).json({ "message": "Request error with CAS" });
                }
            });
        }
        // Otherwise, just destroy the CAS session variables.
        else {
            // @ts-ignore
            delete req.session[EuLogin._sessionName];
            if (EuLogin._sessionInfo) {
                // @ts-ignore
                delete req.session[EuLogin._sessionInfo];
            }
        }

        if (EuLogin._logoutRedirectUrl) {
            return res.redirect(EuLogin._logoutRedirectUrl);
        }
        // Redirect the client to the CAS logout.
        res.redirect(EuLogin._casUrl + '/logout');
    };

    setServiceUrl(serviceUrl: string) {
        EuLogin._serviceUrl = serviceUrl;
    }

    setCasUrl(casUrl: string) {
        EuLogin._casUrl = casUrl;
    }

    setValidateUri(validateUri: string) {
        EuLogin._validateUri = validateUri;
    }

    setCasVersion(casVersion: string) {
        EuLogin._casVersion = casVersion;
    }

    setSessionName(sessionName: string) {
        EuLogin._sessionName = sessionName;
    }

    setSessionInfo(sessionInfo: string) {
        EuLogin._sessionInfo = sessionInfo;
    }

    setDestroySession(destroySession: boolean) {
        EuLogin._destroySession = destroySession;
    }

    setRenew(renew: boolean) {
        EuLogin._renew = renew;
    }

    setIsDevMode(isDevMode: boolean) {
        EuLogin._isDevMode = isDevMode;
    }

    setDevModeUser(devModeUser: string) {
        EuLogin._devModeUser = devModeUser;
    }

    setDevModeInfo(devModeInfo: object) {
        EuLogin._devModeInfo = devModeInfo;
    }

    setAssuranceLevel(assuranceLevel: number) {
        EuLogin._assuranceLevel = assuranceLevel;
    }

    setHttpClient(httpClient: typeof import("https")) {
        EuLogin._httpClient = httpClient;
    }

    setCasHost(casHost: string) {
        EuLogin._casHost = casHost;
    }

    setCasPort(casPort: number) {
        EuLogin._casPort = casPort;
    }

    setCasPath(casPath: string) {
        EuLogin._casPath = casPath;
    }

    setLogoutRedirectUrl(logoutRedirectUrl: string) {
        EuLogin._logoutRedirectUrl = logoutRedirectUrl;
    }

    bounce(req: Request, res: Response, next: NextFunction) {
        // Handle the request with the bounce authorization type.
        EuLogin.handle(req, res, next, EAuthType.BOUNCE);
    }

    bounce_redirect(req: Request, res: Response, next: NextFunction) {
        // Handle the request with the bounce_redirect authorization type.
        EuLogin.handle(req, res, next, EAuthType.BOUNCE_REDIRECT);
    }

    block(req: Request, res: Response, next: NextFunction) {
        // Handle the request with the block authorization type.
        EuLogin.handle(req, res, next, EAuthType.BLOCK);
    }
}