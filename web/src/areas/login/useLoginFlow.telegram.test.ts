import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { TELEGRAM_FAILED, TELEGRAM_UNAVAILABLE, useLoginFlow } from './useLoginFlow'
import { deps, err, view } from './flowFixtures'

const telegramView = () => view('mfa', { factors: ['telegram', 'recovery'] })

async function started() {
  const d = deps()
  d.api.get.mockResolvedValue(telegramView())
  const flow = useLoginFlow('tx-1', d.deps)
  await flow.load()
  return { d, flow }
}

beforeEach(() => vi.useFakeTimers())
afterEach(() => vi.useRealTimers())

describe('useLoginFlow Telegram', () => {
  it('sends a code without leaving the step, then submits it like a TOTP code', async () => {
    const { d, flow } = await started()
    d.api.sendTelegramCode.mockResolvedValue({ sent: true, expires_in: 300 })
    d.api.submitTelegram.mockResolvedValue({ redirect: 'https://shop/cb?code=c' })
    await flow.sendTelegram()
    expect(d.api.sendTelegramCode).toHaveBeenCalledWith('tx-1')
    expect(flow.telegramSent.value).toBe(true)
    expect(flow.notice.value).toBe("We sent a code to your Telegram. It's valid for 5 minutes.")
    expect(flow.view.value?.step).toBe('mfa')
    await flow.telegram(' 123 456 ')
    expect(d.api.submitTelegram).toHaveBeenCalledWith('tx-1', '123456')
    expect(d.navigate).toHaveBeenCalledWith('https://shop/cb?code=c')
  })

  it('says the code was wrong or expired on invalid_code', async () => {
    const { d, flow } = await started()
    d.api.submitTelegram.mockRejectedValue(err(401, 'invalid_code'))
    await flow.telegram('000000')
    expect(flow.error.value).toBe(TELEGRAM_FAILED)
  })

  it('explains a failed delivery and lets the user retry', async () => {
    const { d, flow } = await started()
    d.api.sendTelegramCode
      .mockRejectedValueOnce(err(502, 'delivery_failed'))
      .mockResolvedValueOnce({ sent: true, expires_in: 300 })
    await flow.sendTelegram()
    expect(flow.error.value).toBe("Couldn't send the code via Telegram. Try again.")
    expect(flow.telegramSent.value).toBe(false)
    expect(flow.locked.value).toBe(false)
    await flow.sendTelegram()
    expect(flow.error.value).toBeNull()
    expect(flow.telegramSent.value).toBe(true)
  })

  it('locks sending for Retry-After seconds on 429', async () => {
    const { d, flow } = await started()
    d.api.sendTelegramCode.mockRejectedValue(err(429, 'rate_limited', 2))
    await flow.sendTelegram()
    expect(flow.rateLimited.value).toBe(true)
    await flow.sendTelegram()
    expect(d.api.sendTelegramCode).toHaveBeenCalledTimes(1)
    vi.advanceTimersByTime(2000)
    expect(flow.locked.value).toBe(false)
  })

  it('reloads the step on wrong_step and expires on 404 (unknown transaction)', async () => {
    const { d, flow } = await started()
    d.api.sendTelegramCode.mockRejectedValueOnce(err(409, 'wrong_step'))
    d.api.get.mockResolvedValue(view('consent'))
    await flow.sendTelegram()
    expect(flow.view.value?.step).toBe('consent')
    expect(flow.telegramSent.value).toBe(false)
    d.api.sendTelegramCode.mockRejectedValueOnce(err(404, 'not_found'))
    await flow.sendTelegram()
    expect(flow.phase.value).toBe('expired')
  })

  it('stays on the step when the server has no Telegram bot', async () => {
    const { d, flow } = await started()
    d.api.sendTelegramCode.mockRejectedValue(err(503, 'telegram_unavailable'))
    d.api.submitTelegram.mockRejectedValue(err(503, 'telegram_unavailable'))
    for (const attempt of [() => flow.sendTelegram(), () => flow.telegram('123456')]) {
      await attempt()
      expect(flow.phase.value).toBe('step')
      expect(flow.view.value?.step).toBe('mfa')
      expect(flow.error.value).toBe(TELEGRAM_UNAVAILABLE)
    }
  })
})
