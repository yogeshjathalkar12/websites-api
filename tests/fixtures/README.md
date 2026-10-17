# Fixtures

`wa_flow_templates.json` is the output of `buildFlowDefinition` for every flow in the app's WhatsApp template library
(`raptor-app/src/lib/waTemplates.ts`, in the website repo). Regenerate it after changing a flow there:

```
cd <website repo>/raptor-app
# dump.ts: import { WA_FLOWS, buildFlowDefinition } from './src/lib/waTemplates';
#          write JSON.stringify(WA_FLOWS.map((f) => ({ id: f.id, name: f.name, entry_keyword: f.entry_keyword,
#            match_type: f.match_type, definition: buildFlowDefinition(f) })), null, 1) to this folder
npx esbuild dump.ts --bundle --platform=node --format=cjs --outfile=dump.cjs && node dump.cjs <path>/wa_flow_templates.json
```

`tests/test_whatsapp_flow_templates.py` then walks every path of every flow through the real flow engine.
