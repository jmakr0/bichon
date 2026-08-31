import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ActionDialog } from '../action-dialog'

class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}

vi.stubGlobal('ResizeObserver', ResizeObserverMock)

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}))

vi.mock('@/hooks/use-proxy', () => ({
  default: () => ({ proxyOptions: [] }),
}))

vi.mock('@/api/oauth2/api', () => ({
  create_oauth2: vi.fn(),
  update_oauth2: vi.fn(),
}))

describe('OAuth2 client type selection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('disables and clears the secret for a public client', async () => {
    const user = userEvent.setup()
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })

    render(
      <QueryClientProvider client={queryClient}>
        <ActionDialog open onOpenChange={vi.fn()} />
      </QueryClientProvider>
    )

    const secret = screen.getByPlaceholderText('oauth2.enterYourClientSecret')
    await user.type(secret, 'temporary-secret')
    expect(secret).toHaveValue('temporary-secret')

    await user.click(screen.getByText('oauth2.publicClient'))
    expect(secret).toBeDisabled()
    expect(secret).toHaveValue('')

    await user.click(screen.getByText('oauth2.confidentialClient'))
    expect(secret).toBeEnabled()
    expect(secret).toHaveValue('')
  })
})
