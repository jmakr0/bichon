import { z } from 'zod'

const paramEntry = (t: (key: string) => string) =>
  z.object({
    key: z
      .string({ required_error: t('oauth2.keyIsRequired') })
      .min(1, t('oauth2.keyCannotBeEmpty')),
    value: z
      .string({ required_error: t('oauth2.valueIsRequired') })
      .min(1, t('oauth2.valueCannotBeEmpty')),
  })

const scopeEntry = (t: (key: string) => string) =>
  z.object({
    value: z
      .string({ required_error: t('oauth2.valueIsRequired') })
      .min(1, t('oauth2.valueCannotBeEmpty')),
  })

export type OAuth2ClientType = 'Confidential' | 'Public'

interface OAuth2SchemaOptions {
  isEdit?: boolean
  existingClientType?: OAuth2ClientType
}

export const getOAuth2Schema = (
  t: (key: string) => string,
  options: OAuth2SchemaOptions = {}
) =>
  z
    .object({
      description: z
        .string()
        .max(255, {
          message: t('oauth2.descriptionMustNotExceed255Characters'),
        })
        .optional(),
      client_id: z
        .string({
          required_error: t('oauth2.clientIdIsRequired'),
        })
        .min(1, { message: t('oauth2.clientIdCannotBeEmpty') }),
      client_type: z.enum(['Confidential', 'Public']),
      client_secret: z.string().optional(),
      auth_url: z
        .string({
          required_error: t('oauth2.authorizationUrlIsRequired'),
        })
        .min(1, { message: t('oauth2.authorizationUrlCannotBeEmpty') })
        .url({ message: t('oauth2.invalidAuthorizationUrlFormat') }),
      token_url: z
        .string({
          required_error: t('oauth2.tokenUrlIsRequired'),
        })
        .min(1, { message: t('oauth2.tokenUrlCannotBeEmpty') })
        .url({ message: t('oauth2.invalidTokenUrlFormat') }),
      redirect_uri: z
        .string({
          required_error: t('oauth2.redirectUriIsRequired'),
        })
        .min(1, { message: t('oauth2.redirectUriCannotBeEmpty') })
        .url({ message: t('oauth2.invalidRedirectUriFormat') }),
      scopes: z.array(scopeEntry(t)).optional(),
      extra_params: z.array(paramEntry(t)).optional(),
      enabled: z.boolean(),
      use_proxy: z.number().optional(),
    })
    .superRefine((values, context) => {
      const secret = values.client_secret?.trim()

      if (values.client_type === 'Public' && secret) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['client_secret'],
          message: t('oauth2.clientSecretNotAllowedForPublicClient'),
        })
      }

      const preservesExistingSecret =
        options.isEdit && options.existingClientType === 'Confidential'
      if (
        values.client_type === 'Confidential' &&
        !secret &&
        !preservesExistingSecret
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['client_secret'],
          message: t('oauth2.clientSecretRequiredForConfidentialClient'),
        })
      }
    })

export type OAuth2FormValues = z.infer<ReturnType<typeof getOAuth2Schema>>

export function buildOAuth2Payload(values: OAuth2FormValues) {
  const payload: Record<string, unknown> = {
    description: values.description,
    client_id: values.client_id,
    client_type: values.client_type,
    auth_url: values.auth_url,
    token_url: values.token_url,
    redirect_uri: values.redirect_uri,
    extra_params: values.extra_params?.reduce(
      (result, item) => ({ ...result, [item.key]: item.value }),
      {}
    ),
    scopes: values.scopes?.map((scope) => scope.value),
    enabled: values.enabled,
    use_proxy: values.use_proxy,
  }

  const secret = values.client_secret?.trim()
  if (values.client_type === 'Confidential' && secret) {
    payload.client_secret = values.client_secret
  }

  return payload
}
