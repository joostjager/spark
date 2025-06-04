import { isNode } from "@lightsparkdev/core";
import type { Channel, ClientFactory } from "nice-grpc";
import { retryMiddleware } from "nice-grpc-client-middleware-retry";
import { ClientMiddlewareCall, Metadata } from "nice-grpc-common";
import type {
  Channel as ChannelWeb,
  ClientFactory as ClientFactoryWeb,
} from "nice-grpc-web";
import { isBun, isReactNative } from "../constants.js";
import { NetworkError } from "../errors/types.js";
import { SparkServiceClient, SparkServiceDefinition } from "../proto/lrc20.js";
import { RetryOptions, SparkCallOptions } from "../types/grpc.js";
import { WalletConfigService } from "./config.js";

// TODO: Some sort of client cleanup
export class Lrc20ConnectionManager {
  private config: WalletConfigService;
  private lrc20Client:
    | (SparkServiceClient & { close?: () => void })
    | undefined;

  constructor(config: WalletConfigService) {
    this.config = config;
  }

  public async closeConnection() {
    this.lrc20Client?.close?.();
  }

  private async createChannelWithTLS(address: string, certPath?: string) {
    try {
      if (isNode && !isBun) {
        const grpcModule = await import("nice-grpc");
        const { ChannelCredentials, createChannel } =
          "default" in grpcModule ? grpcModule.default : grpcModule;

        if (certPath) {
          try {
            // Dynamic import for Node.js only
            const fs = await import("fs");
            const cert = fs.readFileSync(certPath);
            return createChannel(address, ChannelCredentials.createSsl(cert));
          } catch (error) {
            console.error("Error reading certificate:", error);
            // Fallback to insecure for development
            return createChannel(
              address,
              ChannelCredentials.createSsl(null, null, null, {
                rejectUnauthorized: false,
              }),
            );
          }
        } else {
          // No cert provided, use insecure SSL for development
          return createChannel(
            address,
            ChannelCredentials.createSsl(null, null, null, {
              rejectUnauthorized: false,
            }),
          );
        }
      } else {
        // Browser environment - nice-grpc-web handles TLS automatically
        const grpcModule = await import("nice-grpc-web");
        const { createChannel, FetchTransport } =
          "default" in grpcModule ? grpcModule.default : grpcModule;
        const { XHRTransport } = await import("./xhr-transport.js");

        return createChannel(
          address,
          isReactNative ? XHRTransport() : FetchTransport(),
        );
      }
    } catch (error) {
      console.error("Channel creation error:", error);
      throw new NetworkError(
        "Failed to create channel",
        {
          url: address,
          operation: "createChannel",
          errorCount: 1,
          errors: error instanceof Error ? error.message : String(error),
        },
        error as Error,
      );
    }
  }

  async createLrc20Client(
    certPath?: string,
  ): Promise<SparkServiceClient & { close?: () => void }> {
    if (this.lrc20Client) {
      return this.lrc20Client;
    }

    const channel = await this.createChannelWithTLS(
      this.config.getLrc20Address(),
      certPath,
    );

    const middleware = this.createMiddleware();
    const client = await this.createGrpcClient<SparkServiceClient>(
      SparkServiceDefinition,
      channel,
      true,
      middleware,
    );

    this.lrc20Client = client;
    return client;
  }

  private createMiddleware() {
    if (isNode) {
      return this.createNodeMiddleware();
    } else {
      return this.createBrowserMiddleware();
    }
  }

  private createNodeMiddleware() {
    return async function* (
      this: Lrc20ConnectionManager,
      call: ClientMiddlewareCall<any, any>,
      options: SparkCallOptions,
    ) {
      return yield* call.next(call.request, {
        ...options,
        metadata: Metadata(options.metadata).set("User-Agent", "spark-js-sdk"),
      });
    }.bind(this);
  }

  private createBrowserMiddleware() {
    return async function* (
      this: Lrc20ConnectionManager,
      call: ClientMiddlewareCall<any, any>,
      options: SparkCallOptions,
    ) {
      return yield* call.next(call.request, {
        ...options,
        metadata: Metadata(options.metadata)
          .set("X-Requested-With", "XMLHttpRequest")
          .set("X-Grpc-Web", "1")
          .set("Content-Type", "application/grpc-web+proto")
          .set("User-Agent", "spark-js-sdk"),
      });
    }.bind(this);
  }

  private async createGrpcClient<T>(
    defintion: SparkServiceDefinition,
    channel: Channel | ChannelWeb,
    withRetries: boolean,
    middleware?: any,
  ): Promise<T & { close?: () => void }> {
    let clientFactory: ClientFactory | ClientFactoryWeb;

    const retryOptions = {
      retry: true,
      retryMaxAttempts: 3,
    };
    let options: RetryOptions = {};
    const isNodeChannel = "close" in channel;

    if (isNode && isNodeChannel && !isBun) {
      const grpcModule = await import("nice-grpc");
      const { openTelemetryClientMiddleware } = await import(
        "nice-grpc-opentelemetry"
      );
      const { createClientFactory } =
        "default" in grpcModule ? grpcModule.default : grpcModule;

      clientFactory = createClientFactory();
      if (withRetries) {
        options = retryOptions;
        clientFactory = clientFactory
          .use(openTelemetryClientMiddleware())
          .use(retryMiddleware);
      }
      if (middleware) {
        clientFactory = clientFactory.use(middleware);
      }
      const client = clientFactory.create(defintion, channel, {
        "*": options,
      }) as T;
      return {
        ...client,
        close: channel.close.bind(channel),
      };
    } else if (!isNodeChannel) {
      const grpcModule = await import("nice-grpc-web");
      const { createClientFactory } =
        "default" in grpcModule ? grpcModule.default : grpcModule;

      clientFactory = createClientFactory();
      if (withRetries) {
        options = retryOptions;
        clientFactory = clientFactory.use(retryMiddleware);
      }
      if (middleware) {
        clientFactory = clientFactory.use(middleware);
      }
      const client = clientFactory.create(defintion, channel, {
        "*": options,
      }) as T;
      return {
        ...client,
        close: undefined,
      };
    } else {
      throw new Error("Channel does not have close in NodeJS environment");
    }
  }
}
