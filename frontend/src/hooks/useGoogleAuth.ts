import { useMutation } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"

import { type GoogleAuthRequest, OauthService } from "@/client"

export const useGoogleAuth = () => {
  const navigate = useNavigate()

  const googleLoginMutation = useMutation({
    mutationFn: async (data: GoogleAuthRequest) => {
      const response = await OauthService.googleLogin({ requestBody: data })
      return response
    },
    onSuccess: (data) => {
      // Store the access token
      localStorage.setItem("access_token", data.access_token)
      // Navigate to home page
      navigate({ to: "/" })
    },
    onError: (error) => {
      console.error("Google OAuth login error:", error)
    },
  })

  return {
    googleLoginMutation,
  }
}
