export const animations = {
  ripple: (event, element) => {
    const ripple = document.createElement('span')
    const rect = element.getBoundingClientRect()
    const size = Math.max(rect.width, rect.height)
    const x = event.clientX - rect.left - size / 2
    const y = event.clientY - rect.top - size / 2

    ripple.style.width = ripple.style.height = `${size}px`
    ripple.style.left = `${x}px`
    ripple.style.top = `${y}px`
    ripple.classList.add('ripple')

    element.appendChild(ripple)

    setTimeout(() => {
      ripple.remove()
    }, 600)
  },

  fadeIn: (element, duration = 200) => {
    element.style.opacity = '0'
    element.style.transform = 'translateY(4px)'
    element.style.transition = `all ${duration}ms ease`

    requestAnimationFrame(() => {
      element.style.opacity = '1'
      element.style.transform = 'translateY(0)'
    })
  },

  fadeOut: (element, duration = 200) => {
    element.style.transition = `all ${duration}ms ease`
    element.style.opacity = '0'
    element.style.transform = 'translateY(4px)'

    setTimeout(() => {
      element.remove()
    }, duration)
  },

  slideIn: (element, direction = 'right', duration = 300) => {
    const transforms = {
      left: 'translateX(-100%)',
      right: 'translateX(100%)',
      top: 'translateY(-100%)',
      bottom: 'translateY(100%)'
    }

    element.style.transform = transforms[direction]
    element.style.transition = `transform ${duration}ms ease`

    requestAnimationFrame(() => {
      element.style.transform = 'translate(0)'
    })
  },

  morph: (element, from, to, duration = 300) => {
    element.style.transition = `all ${duration}ms ease`
    Object.assign(element.style, from)

    requestAnimationFrame(() => {
      Object.assign(element.style, to)
    })
  }
}

export const animationClasses = {
  ripple: 'ripple-effect',
  fadeIn: 'animate-fade-in',
  slideIn: 'animate-slide-in',
  pulse: 'animate-pulse',
  spin: 'animate-spin'
}
