export class SparkSDKError extends Error {
  public readonly context: Record<string, unknown>;
  public readonly originalError?: Error;

  constructor(
    message: string,
    context: Record<string, unknown> = {},
    originalError?: Error,
  ) {
    const msg = getMessage(message, context, originalError);
    super(msg);
    this.name = this.constructor.name;
    this.context = context;
    this.originalError = originalError;

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  public toString(): string {
    return this.message;
  }

  public toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      message: this.message,
      context: this.context,
      originalError: this.originalError
        ? {
            name: this.originalError.name,
            message: this.originalError.message,
            stack: this.originalError.stack,
          }
        : undefined,
      stack: this.stack,
    };
  }
}

function getMessage(
  message: string,
  context: Record<string, unknown> = {},
  originalError?: Error,
) {
  const contextStr = Object.entries(context)
    .map(([key, value]) => `${key}: ${JSON.stringify(value)}`)
    .join(", ");

  const originalErrorStr = originalError
    ? `\nOriginal Error: ${originalError.message}`
    : "";

  return `SparkSDKError: ${message}${contextStr ? `\nContext: ${contextStr}` : ""}${originalErrorStr}`;
}
