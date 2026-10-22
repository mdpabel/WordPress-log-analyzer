type AnalyticsValue = string | number | boolean;

interface Umami {
  track: (eventName: string, data?: Record<string, AnalyticsValue>) => void;
}

declare global {
  interface Window {
    umami?: Umami;
  }
}

export function trackEvent(eventName: string, data?: Record<string, AnalyticsValue>): void {
  if (typeof window === "undefined") return;
  window.umami?.track(eventName, data);
}

export {};
