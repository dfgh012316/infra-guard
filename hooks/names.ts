// What a tool's input may name, checked before it reaches a command line.
export const CONTEXT = /^[-._:@/a-zA-Z0-9]{1,253}$/
export const DNS_NAME = /^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$/
export const SECRET_KEY = /^[-._a-zA-Z0-9]{1,253}$/
export const REPO = /^[\w.-]+\/[\w.-]+$/
