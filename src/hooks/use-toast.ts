import * as React from "react"

type ToasterToast = {
  id: string
  title?: React.ReactNode
  description?: React.ReactNode
  action?: React.ReactNode
  variant?: 'default' | 'destructive'
  duration?: number
}

const toastQueue: ToasterToast[] = []
const listeners: Array<(toast: ToasterToast) => void> = []
let memoryToasts: ToasterToast[] = []

function genId() {
  return Math.random().toString(36).substr(2, 9)
}

function addToQueue(toast: ToasterToast) {
  toastQueue.push(toast)
  listeners.forEach((listener) => {
    listener(toast)
  })
}

function removeFromQueue(id: string) {
  const index = toastQueue.findIndex((t) => t.id === id)
  if (index > -1) {
    toastQueue.splice(index, 1)
  }
  
  const memoryIndex = memoryToasts.findIndex((t) => t.id === id)
  if (memoryIndex > -1) {
    memoryToasts.splice(memoryIndex, 1)
  }
}

type Toast = Omit<ToasterToast, "id">

function toast_({
  title,
  description,
  action,
  variant = "default",
  ...props
}: Toast) {
  const id = genId()

  const newToast: ToasterToast = {
    id,
    title,
    description,
    action,
    variant,
    ...props,
  }

  memoryToasts = [newToast, ...memoryToasts]
  addToQueue(newToast)

  return {
    id,
    dismiss: () => removeFromQueue(id),
    update: (toast: Partial<Toast>) => {
      const index = memoryToasts.findIndex((t) => t.id === id)
      if (index > -1) {
        memoryToasts[index] = { ...memoryToasts[index], ...toast }
        listeners.forEach((listener) => {
          listener(memoryToasts[index])
        })
      }
    },
  }
}

export function useToast() {
  const [toasts, setToasts] = React.useState<ToasterToast[]>(memoryToasts)

  React.useEffect(() => {
    const listener = (toast: ToasterToast) => {
      setToasts((toasts) => [toast, ...toasts])
    }

    listeners.push(listener)
    return () => {
      const index = listeners.indexOf(listener)
      if (index > -1) {
        listeners.splice(index, 1)
      }
    }
  }, [])

  return {
    toasts,
    toast: toast_,
    dismiss: (toastId?: string) => {
      if (toastId) {
        removeFromQueue(toastId)
        setToasts((toasts) => toasts.filter((t) => t.id !== toastId))
      } else {
        setToasts([])
        memoryToasts = []
        toastQueue.length = 0
      }
    },
  }
}

export { toast_ as toast }