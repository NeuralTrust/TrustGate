"use client";

import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { ArrowRight, AlertCircle } from "lucide-react";
import { createGatewayAction } from "@/app/actions";
import { Input } from "@/components/ui/field";
import { Button } from "@/components/ui/button";

function SubmitButton() {
  const { pending } = useFormStatus();
  return (
    <Button type="submit" variant="primary" size="md" loading={pending} className="w-full">
      {!pending && <ArrowRight className="h-4 w-4" />}
      Create gateway
    </Button>
  );
}

export function OnboardingForm() {
  const [state, formAction] = useActionState(
    async (_prev: { error?: string }, formData: FormData) => createGatewayAction(formData),
    {},
  );

  return (
    <form action={formAction} className="flex flex-col gap-3">
      <Input
        name="name"
        placeholder="e.g. production-gateway"
        autoFocus
        autoComplete="off"
        className="h-11 text-[15px]"
      />
      {state.error && (
        <div className="flex items-center gap-2 text-[13px] text-danger">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <span>{state.error}</span>
        </div>
      )}
      <SubmitButton />
    </form>
  );
}
