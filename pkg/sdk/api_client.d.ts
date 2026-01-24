export interface User {
    id: string;
    email: string;
    full_name?: string;
    mfa_enabled: boolean;
}
export interface LoginResponse {
    access_token?: string;
    refresh_token?: string;
    user: User;
    mfa_required?: boolean;
}
export interface ApiError {
    message: string;
    code?: string;
}
export declare class LaventeAuthClient {
    private client;
    private csrfToken;
    constructor(baseURL?: string);
    login(email: string, password: string): Promise<LoginResponse>;
    verifyMfa(userId: string, code: string): Promise<LoginResponse>;
    verifyMfaBackup(userId: string, code: string): Promise<LoginResponse>;
    logout(): Promise<void>;
    getSessions(): Promise<any[]>;
    private getCookie;
}
