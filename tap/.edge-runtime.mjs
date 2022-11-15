import * as fs from 'node:fs'
import { createRequire } from 'node:module'

const { EdgeRuntime } = createRequire(import.meta.url)('edge-runtime')

const script = fs.readFileSync('./tap/run-edge-runtime.js', { encoding: 'utf-8' })

const runtime = new EdgeRuntime()
runtime.evaluate(script)

let stats
do {
  await new Promise((resolve) => setTimeout(resolve, 1000))
  ;({ stats } = runtime.context)
} while (!stats)

if (stats?.failed !== 0) {
  process.exit(1)
}
