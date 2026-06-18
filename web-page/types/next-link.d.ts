import "next/link";

declare module "next/link" {
  interface LinkProps {
    viewTransition?: boolean;
  }
}
