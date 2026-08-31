import { describe, it, expect } from 'vitest'
import { buildOAuth2Payload, getOAuth2Schema } from '../schema'

const t = (key: string) => key

describe('OAuth2 Form Schema', () => {
  const schema = getOAuth2Schema(t)

  const validData = {
    client_id: 'my-client-id',
    client_type: 'Confidential' as const,
    client_secret: 'my-secret',
    auth_url: 'https://accounts.example.com/o/oauth2/auth',
    token_url: 'https://oauth2.example.com/token',
    redirect_uri: 'https://myapp.example.com/oauth2/callback',
    enabled: true,
  }

  describe('client_id field', () => {
    it('rejects empty client_id', () => {
      const result = schema.safeParse({ ...validData, client_id: '' })
      expect(result.success).toBe(false)
    })

    it('accepts valid client_id', () => {
      const result = schema.safeParse(validData)
      expect(result.success).toBe(true)
    })
  })

  describe('client_secret field', () => {
    it('requires a secret for a new confidential client', () => {
      const result = schema.safeParse({
        ...validData,
        client_secret: undefined,
      })
      expect(result.success).toBe(false)
    })

    it('accepts a public client without a secret', () => {
      const result = schema.safeParse({
        ...validData,
        client_type: 'Public',
        client_secret: undefined,
      })
      expect(result.success).toBe(true)
    })

    it('rejects a public client with a secret', () => {
      const result = schema.safeParse({
        ...validData,
        client_type: 'Public',
      })
      expect(result.success).toBe(false)
    })

    it('preserves an existing confidential secret when the field is blank', () => {
      const editSchema = getOAuth2Schema(t, {
        isEdit: true,
        existingClientType: 'Confidential',
      })
      const result = editSchema.safeParse({
        ...validData,
        client_secret: undefined,
      })
      expect(result.success).toBe(true)
    })

    it('requires a new secret when changing public to confidential', () => {
      const editSchema = getOAuth2Schema(t, {
        isEdit: true,
        existingClientType: 'Public',
      })
      const result = editSchema.safeParse({
        ...validData,
        client_secret: undefined,
      })
      expect(result.success).toBe(false)
    })

    it('omits a public client secret from the payload', () => {
      const result = schema.parse({
        ...validData,
        client_type: 'Public',
        client_secret: undefined,
      })
      expect(buildOAuth2Payload(result)).not.toHaveProperty('client_secret')
    })

    it('omits a blank confidential secret from an edit payload', () => {
      const editSchema = getOAuth2Schema(t, {
        isEdit: true,
        existingClientType: 'Confidential',
      })
      const result = editSchema.parse({
        ...validData,
        client_secret: '',
      })
      expect(buildOAuth2Payload(result)).not.toHaveProperty('client_secret')
    })
  })

  describe('auth_url field', () => {
    it('rejects empty auth_url', () => {
      const result = schema.safeParse({ ...validData, auth_url: '' })
      expect(result.success).toBe(false)
    })

    it('rejects invalid URL format for auth_url', () => {
      const result = schema.safeParse({
        ...validData,
        auth_url: 'not-a-url',
      })
      expect(result.success).toBe(false)
    })

    it('accepts valid auth_url', () => {
      const result = schema.safeParse(validData)
      expect(result.success).toBe(true)
    })
  })

  describe('token_url field', () => {
    it('rejects empty token_url', () => {
      const result = schema.safeParse({ ...validData, token_url: '' })
      expect(result.success).toBe(false)
    })

    it('rejects invalid URL format for token_url', () => {
      const result = schema.safeParse({
        ...validData,
        token_url: 'not-a-url',
      })
      expect(result.success).toBe(false)
    })
  })

  describe('redirect_uri field', () => {
    it('rejects empty redirect_uri', () => {
      const result = schema.safeParse({ ...validData, redirect_uri: '' })
      expect(result.success).toBe(false)
    })

    it('rejects invalid URL format for redirect_uri', () => {
      const result = schema.safeParse({
        ...validData,
        redirect_uri: 'not-a-url',
      })
      expect(result.success).toBe(false)
    })
  })

  describe('scopes field', () => {
    it('accepts empty scopes array', () => {
      const result = schema.safeParse({ ...validData, scopes: [] })
      expect(result.success).toBe(true)
    })

    it('accepts valid scopes', () => {
      const result = schema.safeParse({
        ...validData,
        scopes: [{ value: 'https://mail.google.com/' }],
      })
      expect(result.success).toBe(true)
    })

    it('rejects scope with empty value', () => {
      const result = schema.safeParse({
        ...validData,
        scopes: [{ value: '' }],
      })
      expect(result.success).toBe(false)
    })
  })

  describe('extra_params field', () => {
    it('accepts empty extra_params array', () => {
      const result = schema.safeParse({ ...validData, extra_params: [] })
      expect(result.success).toBe(true)
    })

    it('accepts valid extra_params', () => {
      const result = schema.safeParse({
        ...validData,
        extra_params: [{ key: 'access_type', value: 'offline' }],
      })
      expect(result.success).toBe(true)
    })

    it('rejects param with empty key', () => {
      const result = schema.safeParse({
        ...validData,
        extra_params: [{ key: '', value: 'offline' }],
      })
      expect(result.success).toBe(false)
    })

    it('rejects param with empty value', () => {
      const result = schema.safeParse({
        ...validData,
        extra_params: [{ key: 'access_type', value: '' }],
      })
      expect(result.success).toBe(false)
    })
  })

  describe('enabled field', () => {
    it('accepts enabled: true', () => {
      const result = schema.safeParse(validData)
      expect(result.success).toBe(true)
    })

    it('accepts enabled: false', () => {
      const result = schema.safeParse({ ...validData, enabled: false })
      expect(result.success).toBe(true)
    })
  })

  describe('description field', () => {
    it('rejects description longer than 255 characters', () => {
      const result = schema.safeParse({
        ...validData,
        description: 'a'.repeat(256),
      })
      expect(result.success).toBe(false)
    })

    it('accepts description of exactly 255 characters', () => {
      const result = schema.safeParse({
        ...validData,
        description: 'a'.repeat(255),
      })
      expect(result.success).toBe(true)
    })
  })

  describe('use_proxy field', () => {
    it('accepts undefined use_proxy', () => {
      const result = schema.safeParse(validData)
      expect(result.success).toBe(true)
    })

    it('accepts numeric use_proxy', () => {
      const result = schema.safeParse({ ...validData, use_proxy: 1 })
      expect(result.success).toBe(true)
    })
  })
})
