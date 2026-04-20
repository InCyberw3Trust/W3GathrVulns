import React, { createContext, useContext, useState, useCallback } from 'react'
import axios from 'axios'

const AuthCtx = createContext(null)

const TOKEN_KEY = 'w3g_token'

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || null)

  const login = useCallback(async (username, password) => {
    const { data } = await axios.post('/api/v1/auth/login', { username, password })
    localStorage.setItem(TOKEN_KEY, data.access_token)
    setToken(data.access_token)
  }, [])

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY)
    setToken(null)
  }, [])

  return (
    <AuthCtx.Provider value={{ token, login, logout, isAuthenticated: !!token }}>
      {children}
    </AuthCtx.Provider>
  )
}

export const useAuth = () => useContext(AuthCtx)
