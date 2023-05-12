<?php

namespace App\Entity;

use App\Repository\UserRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Serializer\Annotation\Groups;

/**
 * @ORM\Entity(repositoryClass=UserRepository::class)
 * @ORM\Table(name="`user`")
 */
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    /**
     * @ORM\Id
     * @ORM\GeneratedValue
     * @ORM\Column(type="integer")
     */
    private $id;

    /**
     * @ORM\Column(type="string", length=180, unique=true)
     * @Groups({"get_exhibitions_collection"})
     * @Assert\Email
     * @Assert\NotBlank(groups={"registration"})
     * @Assert\Regex(
     * pattern= "/^[a-zA-Z0-9_.-]+@[a-zA-Z0-9-]+\.[a-z]{2,4}$/",
     * message="L'email n'est pas valide")
     * @Groups({"get_user"})
     */
    private $email;

    /**
     * @ORM\Column(type="json")
     * @Assert\NotBlank
     * @Groups({"get_user"})

     */
    private $roles = [];

    /**
     * @var string The hashed password
     * @ORM\Column(type="string")
     * @Assert\NotBlank
     * @Assert\Regex(
     * pattern= "/^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+.]{8,}$/",
     * message= "Le mot de passe doit contenir au moins 8 caractères, dont une majuscule, un chiffre et un caractère spécial.")
     */
    private $password;

    /**
     * @ORM\Column(type="string", length=50)
     * @Groups({"get_exhibitions_collection", "get_exhibition_by_id"})
     * @Assert\NotBlank(groups={"registration"})
     * @Assert\Regex("/^[a-zA-ZÀ-úÀ-ÿÀ-ÖØ-öø-ÿ '-]*$/")
     * @Groups({"get_exhibitions_collection", "get_exhibition_by_id", "get_user","get_exhibition_artwork_artist_by_id", "get_exhibitions_for_home"})
     */
    private $lastname;

    /**
     * @ORM\Column(type="string", length=50)
     * @Assert\NotBlank(groups={"registration"})
     * @Assert\Regex("/^[a-zA-ZÀ-úÀ-ÿÀ-ÖØ-öø-ÿ '-]*$/")
     * @Groups({"get_exhibitions_collection", "get_exhibition_by_id", "get_user","get_exhibition_artwork_artist_by_id", "get_exhibitions_for_home"})
     */
    private $firstname;

    /**
     * @ORM\Column(type="string", length=255, nullable=true)
     * @Groups({"get_exhibitions_collection", "get_exhibition_by_id", "get_user_data", "get_user","get_exhibition_artwork_artist_by_id", "get_exhibitions_for_home"})
     */
    private $nickname;

    /**
     * @ORM\Column(type="string", length=255, nullable=true)
     * @Assert\Url(groups={"registration"})
     * @Groups({"get_exhibitions_collection", "get_exhibition_by_id", "get_user","get_exhibition_artwork_artist_by_id"})
     */
    private $avatar;

    /**
     * @ORM\Column(type="string", length=255, nullable=true)
     * @Groups({"get_exhibitions_collection", "get_exhibition_by_id","get_exhibition_artwork_artist_by_id"})
     */
    private $slug;

    /**
     * @ORM\OneToMany(targetEntity=Exhibition::class, mappedBy="artist", orphanRemoval=true)
     */
    private $exhibition;

    /**
     * @ORM\Column(type="date", nullable=true)
     * @Groups("get_user")
     */
    private $dateOfBirth;

    /**
     * @ORM\Column(type="string", length=800, nullable=true)
     * @Groups({"get_user", "get_exhibitions_collection", "get_exhibition_by_id","get_exhibition_artwork_artist_by_id"})
     */
    private $presentation;

    /**
     * @ORM\ManyToMany(targetEntity=Artwork::class, mappedBy="favorites")
     */
    private $favorites;

    public function __construct()
    {
        $this->exhibition = new ArrayCollection();
        $this->favorites = new ArrayCollection();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(string $email): self
    {
        $this->email = $email;

        return $this;
    }

    /**
     * A visual identifier that represents this user.
     *
     * @see UserInterface
     */
    public function getUserIdentifier(): string
    {
        return (string) $this->email;
    }

    /**
     * @deprecated since Symfony 5.3, use getUserIdentifier instead
     */
    public function getUsername(): string
    {
        return (string) $this->email;
    }

    /**
     * @see UserInterface
     */
    public function getRoles(): array
    {
        $roles = $this->roles;
        // guarantee every user at least has ROLE_USER
        // $roles[] = "ROLE_ARTIST";

        return array_unique($roles);
    }

    public function setRoles(array $roles): self
    {
        $this->roles = $roles;

        return $this;
    }

    /**
     * @see PasswordAuthenticatedUserInterface
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    public function setPassword(string $password): self
    {
        $this->password = $password;

        return $this;
    }

    /**
     * Returning a salt is only needed, if you are not using a modern
     * hashing algorithm (e.g. bcrypt or sodium) in your security.yaml.
     *
     * @see UserInterface
     */
    public function getSalt(): ?string
    {
        return null;
    }

    /**
     * @see UserInterface
     */
    public function eraseCredentials()
    {
        // If you store any temporary, sensitive data on the user, clear it here
        // $this->plainPassword = null;
    }

    public function getLastname(): ?string
    {
        return $this->lastname;
    }

    public function setLastname(string $lastname): self
    {
        $this->lastname = $lastname;

        return $this;
    }

    public function getFirstname(): ?string
    {
        return $this->firstname;
    }

    public function setFirstname(string $firstname): self
    {
        $this->firstname = $firstname;

        return $this;
    }

    public function getNickname(): ?string
    {
        return $this->nickname;
    }

    public function setNickname(?string $nickname): self
    {
        $this->nickname = $nickname;

        return $this;
    }

    public function getAvatar(): ?string
    {
        return $this->avatar;
    }

    public function setAvatar(?string $avatar): self
    {
        $this->avatar = $avatar;

        return $this;
    }

    public function getSlug(): ?string
    {
        return $this->slug;
    }

    public function setSlug(?string $slug): self
    {
        $this->slug = $slug;

        return $this;
    }

    /**
     * @return Collection<int, Exhibition>
     */
    public function getExhibition(): Collection
    {
        return $this->exhibition;
    }

    public function addExhibition(Exhibition $exhibition): self
    {
        if (!$this->exhibition->contains($exhibition)) {
            $this->exhibition[] = $exhibition;
            $exhibition->setArtist($this);
        }

        return $this;
    }

    public function removeExhibition(Exhibition $exhibition): self
    {
        if ($this->exhibition->removeElement($exhibition)) {
            // set the owning side to null (unless already changed)
            if ($exhibition->getArtist() === $this) {
                $exhibition->setArtist(null);
            }
        }

        return $this;
    }

    public function getDateOfBirth(): ?\DateTimeInterface
    {
        return $this->dateOfBirth;
    }

    public function setDateOfBirth(?\DateTimeInterface $dateOfBirth): self
    {
        $this->dateOfBirth = $dateOfBirth;

        return $this;
    }

    public function getPresentation(): ?string
    {
        return $this->presentation;
    }

    public function setPresentation(?string $presentation): self
    {
        $this->presentation = $presentation;

        return $this;
    }

    /**
     * @return Collection<int, Artwork>
     */
    public function getFavorites(): Collection
    {
        return $this->favorites;
    }

    public function addFavorite(Artwork $favorite): self
    {
        if (!$this->favorites->contains($favorite)) {
            $this->favorites[] = $favorite;
            $favorite->addFavorite($this);
        }

        return $this;
    }

    public function removeFavorite(Artwork $favorite): self
    {
        if ($this->favorites->removeElement($favorite)) {
            $favorite->removeFavorite($this);
        }

        return $this;
    }
}
