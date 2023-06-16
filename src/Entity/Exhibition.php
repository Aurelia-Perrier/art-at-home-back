<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use App\Repository\ExhibitionRepository;
use DateTime;
use Doctrine\Common\Collections\Collection;
use Doctrine\Common\Collections\ArrayCollection;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Serializer\Annotation\Groups;

/**
 * @ORM\Entity(repositoryClass=ExhibitionRepository::class)
 * 
 */
class Exhibition
{
    /**
     * @ORM\Id
     * @ORM\GeneratedValue
     * @ORM\Column(type="integer")
     * @Groups({"get_exhibitions_collection", "get_artwork_by_exhibition"})
     */
    private $id;

    /**
     * @ORM\Column(type="string", length=255)
     * @Groups({"get_exhibitions_collection","get_artwork_by_exhibition"})
     * @Assert\NotBlank
     */
    private $title;

    /**
     * @ORM\Column(type="string", length=255, nullable=true)
     * @Groups({"get_exhibitions_collection"})
     */
    private $slug;

    /**
     * @ORM\Column(type="date", nullable=true)
     * @Groups({"get_exhibitions_collection"})
     */
    private $startDate;

    /**
     * @ORM\Column(type="date", nullable=true)
     * @Groups({"get_exhibitions_collection"})
     */
    private $endDate;

    /**
     * @ORM\Column(type="boolean", nullable=true)
     * @Groups({"get_exhibitions_collection"})
     */
    private $status;

    /**
     * @ORM\OneToMany(targetEntity=Artwork::class, mappedBy="exhibition", orphanRemoval=true)
     * @Groups({"get_exhibitions_collection"})
     * @ORM\JoinColumn(onDelete="SET NULL")
     */
    private $artwork;

    /**
     * @ORM\ManyToOne(targetEntity=User::class, inversedBy="exhibition")
     * @ORM\JoinColumn(nullable=false)
     * @Groups({"get_exhibitions_collection"})
     * @Assert\NotBlank
     */
    private $artist;

    /**
     * @ORM\Column(type="text", nullable=true)
     * @Groups({"get_exhibitions_collection"})
     */
    private $description;

    public function __construct()
    {
        $this->artwork = new ArrayCollection();
        $this->startDate  = new DateTime();
        $this->status = 1;
        $this->endDate = date_add(new DateTime(), date_interval_create_from_date_string("122 days"));
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getTitle(): ?string
    {
        return $this->title;
    }

    public function setTitle(string $title): self
    {
        $this->title = $title;

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

    public function getStartDate(): ?\DateTimeInterface
    {
        return $this->startDate;
    }

    public function setStartDate(?\DateTimeInterface $startDate): self
    {
        $this->startDate = $startDate;

        return $this;
    }

    public function getEndDate(): ?\DateTimeInterface
    {
        return $this->endDate;
    }

    public function setEndDate(?\DateTimeInterface $endDate): self
    {
        $this->endDate = $endDate;

        return $this;
    }

    public function isStatus(): ?bool
    {
        return $this->status;
    }

    public function setStatus(?bool $status): self
    {
        $this->status = $status;

        return $this;
    }

    /**
     * @return Collection<int, Artwork>
     */
    public function getArtwork(): Collection
    {
        return $this->artwork;
    }

    public function addArtwork(Artwork $artwork): self
    {
        if (!$this->artwork->contains($artwork)) {
            $this->artwork[] = $artwork;
            $artwork->setExhibition($this);
        }

        return $this;
    }

    public function removeArtwork(Artwork $artwork): self
    {
        if ($this->artwork->removeElement($artwork)) {
            // set the owning side to null (unless already changed)
            if ($artwork->getExhibition() === $this) {
                $artwork->setExhibition(null);
            }
        }

        return $this;
    }

    public function getArtist(): ?User
    {
        return $this->artist;
    }

    public function setArtist(?User $artist): self
    {
        $this->artist = $artist;

        return $this;
    }

    public function getDescription(): ?string
    {
        return $this->description;
    }

    public function setDescription(?string $description): self
    {
        $this->description = $description;

        return $this;
    }
}
