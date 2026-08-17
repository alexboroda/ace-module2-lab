/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns/promises'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIPv4 (ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(isNaN)) {
    return true
  }
  const [a, b, c, d] = parts
  if (a === 127) return true
  if (a === 10) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 169 && b === 254) return true
  if (a === 0) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  return false
}

function isPrivateIPv6 (ip: string): boolean {
  const normalized = ip.toLowerCase().trim()
  if (normalized === '::1' || normalized === '::') {
    return true
  }
  if (
    normalized.startsWith('fc') ||
    normalized.startsWith('fd') ||
    normalized.startsWith('fe8') ||
    normalized.startsWith('fe9') ||
    normalized.startsWith('fea') ||
    normalized.startsWith('feb')
  ) {
    return true
  }
  if (normalized.startsWith('::ffff:')) {
    const ipv4Part = ip.slice(7)
    if (net.isIPv4(ipv4Part)) {
      return isPrivateIPv4(ipv4Part)
    }
  }
  return false
}

function isPrivateIP (ip: string): boolean {
  if (net.isIPv4(ip)) {
    return isPrivateIPv4(ip)
  }
  if (net.isIPv6(ip)) {
    return isPrivateIPv6(ip)
  }
  return true
}

async function isSafeUrl (urlStr: string): Promise<boolean> {
  try {
    const parsedUrl = new URL(urlStr)
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false
    }
    let hostname = parsedUrl.hostname
    if (!hostname) {
      return false
    }
    if (hostname.startsWith('[') && hostname.endsWith(']')) {
      hostname = hostname.slice(1, -1)
    }
    if (net.isIP(hostname)) {
      if (isPrivateIP(hostname)) {
        return false
      }
    } else {
      try {
        const addresses = await dns.lookup(hostname, { all: true })
        for (const addr of addresses) {
          if (isPrivateIP(addr.address)) {
            return false
          }
        }
      } catch {
        return false
      }
    }
    return true
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (typeof url !== 'string') {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }

      let isChallengeUrl = false
      try {
        const parsedUrl = new URL(url)
        let hostname = parsedUrl.hostname.toLowerCase()
        if (hostname.startsWith('[') && hostname.endsWith(']')) {
          hostname = hostname.slice(1, -1)
        }
        const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1'
        const isChallengePath = parsedUrl.pathname === '/solve/challenges/server-side' || parsedUrl.pathname === '/solve/challenges/server-side/'
        isChallengeUrl = isLocalhost && isChallengePath
      } catch {
        isChallengeUrl = false
      }

      if (isChallengeUrl) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (!isChallengeUrl && !(await isSafeUrl(url))) {
          next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
          return
        }

        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
