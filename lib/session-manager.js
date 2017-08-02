class SessionManager {
    constructor(logger) {
        this.sessionMap = new Map();

        if (logger) {
            this.log = logger;
        } else {
            this.log = {
                info: console.info,
                debug: console.debug,
                trace: console.trace,
                warn: console.warn,
                error: console.error
            };
        }
    }

    setSession(userId, password, sessionId) {
        this.sessionMap.set(this._createSessionKey(userId, password), sessionId);
    }

    clearSession(userId, password){
        this.sessionMap.delete(this._createSessionKey(userId ,password));
    }

    /**
     * Returns undefined if no session key is present
     *
     * @param userId
     * @param password
     * @returns {V}
     */
    getSession(userId, password) {
        return this.sessionMap.get(this._createSessionKey(userId, password));
    }

    _createSessionKey(userId, password){
        return userId + password;
    }

    getNumSessions(){
        return this.sessionMap.size;
    }
}

module.exports = SessionManager;