/**
 * The authorization channel must stay out of the agent's reach (SPEC.md §4.2, §7).
 *
 * The Stage A link is a capability: whoever holds it can complete the human's
 * half of the flow. A compromised agent with a shell or an HTTP tool is exactly
 * the threat model of SPEC.md §18.1, so by default Veil hands that link to the
 * user's browser and gives the agent only a request id.
 */

import { describe, expect, it } from 'vitest';

import { AdapterRegistry } from '../../../src/adapters/registry.js';
import { RecordingAdapter } from '../../support/fakes.js';
import { Harness, storeArgs, testConfig } from '../../support/harness.js';

describe('out-of-band authorization', () => {
  it('does not disclose the authorization URL to the agent', async () => {
    const config = testConfig({ discloseAuthorizationUrl: false });
    const adapter = new RecordingAdapter(config);
    const harness = await Harness.start(config, new AdapterRegistry([adapter]));
    try {
      const payload = await harness.callTool('secret_store', storeArgs());
      const status = await harness.status(payload.request_id as string);

      expect(payload.authorization_url).toBeUndefined();
      expect(status.authorization_url).toBeUndefined();
      expect(String(payload.authorization)).toContain('deliberately not shared with you');

      const request = harness.broker.get(payload.request_id);
      const rendered = JSON.stringify([payload, status]);
      expect(rendered).not.toContain(request.submitToken);
      expect(rendered).not.toContain(request.confirmToken);
    } finally {
      await harness.stop();
    }
  });

  it('notifies the human through the UI rather than through MCP', async () => {
    const config = testConfig({ discloseAuthorizationUrl: false });
    const adapter = new RecordingAdapter(config);
    const harness = await Harness.start(config, new AdapterRegistry([adapter]));
    const presented: [string, string][] = [];
    try {
      harness.broker.setAuthorizationNotifier((requestId, url) => presented.push([requestId, url]));
      const payload = await harness.callTool('secret_store', storeArgs());

      expect(presented).toHaveLength(1);
      const [requestId, url] = presented[0] as [string, string];
      expect(requestId).toBe(payload.request_id);
      expect(url).toContain(harness.broker.get(requestId).submitToken);
    } finally {
      await harness.stop();
    }
  });
});
