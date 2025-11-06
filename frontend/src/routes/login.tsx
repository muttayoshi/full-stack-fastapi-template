import {
  Container,
  Image,
  Input,
  Separator,
  Stack,
  Text,
} from "@chakra-ui/react"
import { useGoogleLogin } from "@react-oauth/google"
import {
  createFileRoute,
  Link as RouterLink,
  redirect,
} from "@tanstack/react-router"
import { useState } from "react"
import { type SubmitHandler, useForm } from "react-hook-form"
import { FcGoogle } from "react-icons/fc"
import { FiLock, FiMail } from "react-icons/fi"

import type { Body_login_login_access_token as AccessToken } from "@/client"
import { Button } from "@/components/ui/button"
import { Field } from "@/components/ui/field"
import { InputGroup } from "@/components/ui/input-group"
import { PasswordInput } from "@/components/ui/password-input"
import useAuth, { isLoggedIn } from "@/hooks/useAuth"
import { useGoogleAuth } from "@/hooks/useGoogleAuth"
import Logo from "/assets/images/fastapi-logo.svg"
import { emailPattern, passwordRules } from "../utils"

export const Route = createFileRoute("/login")({
  component: Login,
  beforeLoad: async () => {
    if (isLoggedIn()) {
      throw redirect({
        to: "/",
      })
    }
  },
})

function Login() {
  const { loginMutation, error, resetError } = useAuth()
  const { googleLoginMutation } = useGoogleAuth()
  const [isGoogleLoading, setIsGoogleLoading] = useState(false)

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<AccessToken>({
    mode: "onBlur",
    criteriaMode: "all",
    defaultValues: {
      username: "",
      password: "",
    },
  })

  const onSubmit: SubmitHandler<AccessToken> = async (data) => {
    if (isSubmitting) return

    resetError()

    try {
      await loginMutation.mutateAsync(data)
    } catch {
      // error is handled by useAuth hook
    }
  }

  const handleGoogleLogin = useGoogleLogin({
    onSuccess: async (codeResponse) => {
      setIsGoogleLoading(true)
      try {
        await googleLoginMutation.mutateAsync({ code: codeResponse.code })
      } catch (error) {
        console.error("Google login failed:", error)
      } finally {
        setIsGoogleLoading(false)
      }
    },
    onError: (error) => {
      console.error("Google login error:", error)
      setIsGoogleLoading(false)
    },
    flow: "auth-code",
  })

  return (
    <Container
      as="form"
      onSubmit={handleSubmit(onSubmit)}
      h="100vh"
      maxW="sm"
      alignItems="stretch"
      justifyContent="center"
      gap={4}
      centerContent
    >
      <Image
        src={Logo}
        alt="FastAPI logo"
        height="auto"
        maxW="2xs"
        alignSelf="center"
        mb={4}
      />

      {/* Google OAuth Button */}
      <Button
        variant="outline"
        size="md"
        onClick={() => handleGoogleLogin()}
        loading={isGoogleLoading}
        w="100%"
      >
        <FcGoogle size={20} />
        <Text ml={2}>Continue with Google</Text>
      </Button>

      <Stack direction="row" align="center" w="100%">
        <Separator flex="1" />
        <Text px={2} color="fg.muted" fontSize="sm">
          OR
        </Text>
        <Separator flex="1" />
      </Stack>

      <Field
        invalid={!!errors.username}
        errorText={errors.username?.message || !!error}
      >
        <InputGroup w="100%" startElement={<FiMail />}>
          <Input
            {...register("username", {
              required: "Username is required",
              pattern: emailPattern,
            })}
            placeholder="Email"
            type="email"
          />
        </InputGroup>
      </Field>
      <PasswordInput
        type="password"
        startElement={<FiLock />}
        {...register("password", passwordRules())}
        placeholder="Password"
        errors={errors}
      />
      <RouterLink to="/recover-password" className="main-link">
        Forgot Password?
      </RouterLink>
      <Button variant="solid" type="submit" loading={isSubmitting} size="md">
        Log In
      </Button>
      <Text>
        Don't have an account?{" "}
        <RouterLink to="/signup" className="main-link">
          Sign Up
        </RouterLink>
      </Text>
    </Container>
  )
}
